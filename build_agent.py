# build_agent.py
#import frida
import sys
import os
#import argparse
import re

def _strip_export_keyword(code_snippet: str) -> str:
    # Remove a leading 'export ' if present
    return re.sub(r'^\s*export\s+', '', code_snippet)

def _extract_until_semicolon(src: str, start_idx: int) -> str:
    end_idx = src.find(';', start_idx)
    return src[start_idx:(end_idx + 1 if end_idx != -1 else len(src))]

def _extract_braced_block(src: str, start_idx: int) -> str:
    # Find first '{' then balance braces
    brace_idx = src.find('{', start_idx)
    if brace_idx == -1:
        return _extract_until_semicolon(src, start_idx)
    depth = 0
    i = brace_idx
    while i < len(src):
        ch = src[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return src[start_idx:i + 1]
        i += 1
    return src[start_idx:]

def _find_decl_for_name(src: str, name: str) -> str | None:
    # 1) export function NAME(...)
    m = re.search(rf'\bexport\s+function\s+{re.escape(name)}\s*\(', src)
    if m:
        return _strip_export_keyword(_extract_braced_block(src, m.start()))
    # 2) function NAME(...)
    m = re.search(rf'\bfunction\s+{re.escape(name)}\s*\(', src)
    if m:
        return _extract_braced_block(src, m.start())

    # 3) export const/let/var NAME = ...
    for kw in ('const', 'let', 'var'):
        m = re.search(rf'\bexport\s+{kw}\s+{re.escape(name)}\b', src)
        if m:
            return _strip_export_keyword(_extract_until_semicolon(src, m.start()))
        m = re.search(rf'\b{kw}\s+{re.escape(name)}\b', src)
        if m:
            return _extract_until_semicolon(src, m.start())

    # 4) export { NAME, ... } — re-exports: not followed here (needs deeper resolution)
    return None

def _collect_import_blocks(src: str) -> list[tuple[list[str], str, tuple[int,int]]]:
    """
    Finds multiline imports:
    import {
        A,
        B,
    } from './utils.js';
    Returns [(names[], module_path, (start_idx, end_idx)), ...]
    """
    pattern = re.compile(
        r'^\s*import\s*{\s*([\s\S]*?)\s*}\s*from\s*[\'"](.+?)[\'"]\s*;?\s*',
        re.MULTILINE
    )
    imports = []
    for m in pattern.finditer(src):
        raw_names = m.group(1)
        names = [n.strip() for n in re.split(r',', raw_names) if n.strip()]
        mod = m.group(2)
        imports.append((names, mod, (m.start(), m.end())))
    return imports

def simple_compose(main_path: str) -> str:
    with open(main_path, encoding="utf-8") as f:
        main_code = f.read()

    imports = _collect_import_blocks(main_code)

    # Collect declarations to inject
    injected_chunks: list[str] = []
    seen: set[str] = set()
    for names, mod_rel, _span in imports:
        dep_path = os.path.join(os.path.dirname(main_path), mod_rel)
        with open(dep_path, encoding="utf-8") as dep:
            dep_code = dep.read()
        for name in names:
            if name in seen:
                continue
            decl = _find_decl_for_name(dep_code, name)
            if decl:
                injected_chunks.append(decl)
                seen.add(name)
            else:
                injected_chunks.append(f'// [warn] Not found: {name} in {mod_rel}')

    # Remove import blocks from main_code
    if imports:
        # Build a mask of ranges to remove
        to_remove = []
        for _, _, span in imports:
            to_remove.append(span)
        # Merge and cut
        to_remove.sort()
        out = []
        last = 0
        for s, e in to_remove:
            out.append(main_code[last:s])
            last = e
        out.append(main_code[last:])
        main_without_imports = ''.join(out)
    else:
        main_without_imports = main_code

    # Inline simple require(...) lines by file content
    output_lines: list[str] = []
    output_lines.extend(injected_chunks)
    output_lines.append('')  # separator

    for line in main_without_imports.splitlines():
        if 'require(' in line:
            try:
                dep_file = line.split('require(')[1].split(')')[0].strip('\'"')
                dep_path = os.path.join(os.path.dirname(main_path), dep_file)
                with open(dep_path, encoding='utf-8') as dep:
                    output_lines.append(dep.read())
                continue
            except Exception as e:
                output_lines.append(f'// [warn] require load failed: {e}')
                continue
        output_lines.append(line)

    return '\n'.join(output_lines)

def build_agent(agent_path: str):
    if not os.path.isfile(agent_path):
        print(f"[!] Файл не найден: {agent_path}")
        return

    try:
        
        # compiler = frida.Compiler()
        # bundle = compiler.build(agent_path, 
        #                         project_root=os.path.dirname(agent_path), 
        #                        # bundle_format = "iife",
        #                         source_maps="omitted") # ← отключает source map
        
        
        bundle = simple_compose(agent_path)
        # bundle = post_build_bundle_clear(bundle)

        # Определяем имя выходного файла
        agent_name = os.path.basename(agent_path).rsplit('.', 1)[0]
        output_path = os.path.join("bundles", f"{agent_name}-agent.js")

        os.makedirs("bundles", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(bundle)

        print(f"[+] Собрано: {output_path}")

        return output_path

    except Exception as e:
        print(f"[-] Ошибка сборки: {e}")
        return None
    
def post_build_bundle_clear(js_code: str) -> str:
    """
    Удаляет:
    - блоки между 📦 и ✄ (включительно)
    - все строки, начинающиеся с 'import'
    - сам символ ✄, если он встречается отдельно
    """
    lines = js_code.splitlines()
    cleaned = []
    skip = False
    for line in lines:
        stripped = line.strip()
        # начало блока 📦
        if stripped.startswith("📦"):
            skip = True
            continue
        # конец блока ✄
        if skip and stripped.startswith("✄"):
            skip = False
            continue
        # пропускаем строки с import
        if stripped.startswith("import "):
            continue
        # пропускаем одиночный ✄
        if stripped == "✄":
            continue
        if not skip:
            cleaned.append(line)
    return "\n".join(cleaned)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python build_agent.py <путь_к_агенту.js>")
        sys.exit(1)

    agent_path = sys.argv[1]
    build_agent(agent_path)
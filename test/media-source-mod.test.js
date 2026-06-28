import test from 'ava';
import { buildServiceToPageNameMap, buildServiceConfig } from '../agents/media-source-mod.js';

// Tests for buildServiceToPageNameMap

test('buildServiceToPageNameMap returns page names for valid configuration', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
            XMLA_MUSIC: { pageName: 'com.example.xmla' },
            RADIO_YUNTING: { pageName: 'com.example.radio' },
        },
    };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {
        WECAR_FLOW: 'com.example.wecar',
        XMLA_MUSIC: 'com.example.xmla',
        RADIO_YUNTING: 'com.example.radio',
    });
});

test('buildServiceToPageNameMap returns empty object for null config', (t) => {
    const result = buildServiceToPageNameMap(null);
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap returns empty object for undefined config', (t) => {
    const result = buildServiceToPageNameMap(undefined);
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap returns empty object for missing media property', (t) => {
    const config = { other: 'property' };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap returns empty object for empty media object', (t) => {
    const config = { media: {} };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap handles invalid pageName values', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: '' },
            XMLA_MUSIC: { pageName: null },
            RADIO_YUNTING: { pageName: undefined },
        },
    };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap handles mixed valid and invalid entries', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
            XMLA_MUSIC: { pageName: '' },
            RADIO_YUNTING: { pageName: 'com.example.radio' },
        },
    };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {
        WECAR_FLOW: 'com.example.wecar',
        RADIO_YUNTING: 'com.example.radio',
    });
});

test('buildServiceToPageNameMap handles special characters in page names', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.app-test_v2' },
        },
    };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {
        WECAR_FLOW: 'com.example.app-test_v2',
    });
});

test('buildServiceToPageNameMap handles service without pageName property', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { otherProperty: 'value' },
            XMLA_MUSIC: { pageName: 'com.example.xmla' },
        },
    };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {
        XMLA_MUSIC: 'com.example.xmla',
    });
});

test('buildServiceToPageNameMap handles non-object media property', (t) => {
    const config = { media: 'not an object' };
    const result = buildServiceToPageNameMap(config);
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap handles non-object config', (t) => {
    const result = buildServiceToPageNameMap('not an object');
    t.deepEqual(result, {});
});

test('buildServiceToPageNameMap handles array as config', (t) => {
    const result = buildServiceToPageNameMap([]);
    t.deepEqual(result, {});
});

// Tests for buildServiceConfig

test('buildServiceConfig returns enabled services for valid configuration', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar', autoPlay: true },
            XMLA_MUSIC: { pageName: 'com.example.xmla', autoPlay: false },
        },
    };
    const services = [
        { name: 'WECAR_FLOW', media: 'mediaEnum1' },
        { name: 'XMLA_MUSIC', media: 'mediaEnum2' },
    ];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 2);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, true);
    t.is(result[1].name, 'XMLA_MUSIC');
    t.is(result[1].enable, true);
    t.is(result[1].autoPlay, false);
});

test('buildServiceConfig returns disabled services for missing config', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const services = [
        { name: 'WECAR_FLOW', media: 'mediaEnum1' },
        { name: 'XMLA_MUSIC', media: 'mediaEnum2' },
    ];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 2);
    t.is(result[0].enable, true);
    t.is(result[1].enable, false);
    t.is(result[1].autoPlay, false);
});

test('buildServiceConfig returns disabled services (not an empty array) for null config', (t) => {
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(null, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig returns disabled services (not an empty array) for undefined config', (t) => {
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(undefined, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig returns empty array for null services', (t) => {
    const config = { media: { WECAR_FLOW: { pageName: 'com.example.wecar' } } };
    const result = buildServiceConfig(config, null);
    t.deepEqual(result, []);
});

test('buildServiceConfig returns empty array for undefined services', (t) => {
    const config = { media: { WECAR_FLOW: { pageName: 'com.example.wecar' } } };
    const result = buildServiceConfig(config, undefined);
    t.deepEqual(result, []);
});

test('buildServiceConfig returns empty array for non-array services', (t) => {
    const config = { media: { WECAR_FLOW: { pageName: 'com.example.wecar' } } };
    const result = buildServiceConfig(config, 'not an array');
    t.deepEqual(result, []);
});

test('buildServiceConfig handles empty services array', (t) => {
    const config = { media: { WECAR_FLOW: { pageName: 'com.example.wecar' } } };
    const result = buildServiceConfig(config, []);
    t.deepEqual(result, []);
});

test('buildServiceConfig handles missing media property in config', (t) => {
    const config = { other: 'property' };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles empty media object', (t) => {
    const config = { media: {} };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles empty pageName', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: '' },
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles missing pageName property', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { autoPlay: true },
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles autoPlay not set', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles autoPlay explicitly false', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar', autoPlay: false },
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles autoPlay explicitly true', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar', autoPlay: true },
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, true);
});

test('buildServiceConfig preserves service properties', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar', autoPlay: true },
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1', customProp: 'value' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].media, 'mediaEnum1');
    t.is(result[0].customProp, 'value');
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, true);
});

test('buildServiceConfig handles multiple services with mixed configurations', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar', autoPlay: true },
            XMLA_MUSIC: { pageName: '' },
            RADIO_YUNTING: { pageName: 'com.example.radio', autoPlay: false },
        },
    };
    const services = [
        { name: 'WECAR_FLOW', media: 'mediaEnum1' },
        { name: 'XMLA_MUSIC', media: 'mediaEnum2' },
        { name: 'RADIO_YUNTING', media: 'mediaEnum3' },
    ];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 3);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, true);
    t.is(result[1].name, 'XMLA_MUSIC');
    t.is(result[1].enable, false);
    t.is(result[1].autoPlay, false);
    t.is(result[2].name, 'RADIO_YUNTING');
    t.is(result[2].enable, true);
    t.is(result[2].autoPlay, false);
});

test('buildServiceConfig handles non-object service data', (t) => {
    const config = {
        media: {
            WECAR_FLOW: 'not an object',
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles null service data', (t) => {
    const config = {
        media: {
            WECAR_FLOW: null,
        },
    };
    const services = [{ name: 'WECAR_FLOW', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].name, 'WECAR_FLOW');
    t.is(result[0].enable, false);
    t.is(result[0].autoPlay, false);
});

test('buildServiceConfig handles service names with special characters', (t) => {
    const config = {
        media: {
            'WECAR-FLOW_V2': { pageName: 'com.example.wecar', autoPlay: true },
        },
    };
    const services = [{ name: 'WECAR-FLOW_V2', media: 'mediaEnum1' }];
    const result = buildServiceConfig(config, services);
    t.is(result.length, 1);
    t.is(result[0].enable, true);
    t.is(result[0].autoPlay, true);
});

import test from 'ava';
import { buildMediaEnumConfig } from '../agents/media-window-mod.js';

test('returns success with valid configuration and mutates the matching enum', (t) => {
    const config = {
        media: {
            WECAR_FLOW: {
                pageName: 'com.example.wecar',
                serviceName: 'WeCarFlow',
                servicePageName: 'WeCarPage',
                clientId: 'wecar123',
            },
        },
    };
    const services = ['WECAR_FLOW'];
    const enums = {
        WECAR_FLOW: { service: {}, enable: false },
    };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.is(result.configured.length, 1);
    t.is(result.configured[0].serviceName, 'WECAR_FLOW');
    t.is(result.configured[0].pageName, 'com.example.wecar');
    t.is(result.configured[0].serviceName_, 'WeCarFlow');
    t.is(result.configured[0].servicePageName, 'WeCarPage');
    t.is(result.configured[0].clientId, 'wecar123');

    // The shared enums object must actually be mutated, matching what
    // changeMediaEnum() needs in production.
    t.is(enums.WECAR_FLOW.service.pageName, 'com.example.wecar');
    t.is(enums.WECAR_FLOW.service.serviceName, 'WeCarFlow');
    t.is(enums.WECAR_FLOW.service.servicePageName, 'WeCarPage');
    t.is(enums.WECAR_FLOW.service.clientId, 'wecar123');
    t.is(enums.WECAR_FLOW.enable, true);
});

test('handles null config', (t) => {
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    const result = buildMediaEnumConfig(null, services, enums);

    t.is(result.success, false);
    t.deepEqual(result.configured, []);
});

test('handles non-object config parameter', (t) => {
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    t.deepEqual(buildMediaEnumConfig('not an object', services, enums), {
        success: false,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig(123, services, enums), {
        success: false,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig(undefined, services, enums), {
        success: false,
        configured: [],
    });
});

test('handles config without a valid media property', (t) => {
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    t.deepEqual(buildMediaEnumConfig({ other: 'data' }, services, enums), {
        success: false,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig({ media: 'not an object' }, services, enums), {
        success: false,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig({ media: null }, services, enums), {
        success: false,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig({}, services, enums), {
        success: false,
        configured: [],
    });
});

test('handles invalid services parameter', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    t.deepEqual(buildMediaEnumConfig(config, [], enums), { success: false, configured: [] });
    t.deepEqual(buildMediaEnumConfig(config, null, enums), { success: false, configured: [] });
    t.deepEqual(buildMediaEnumConfig(config, 'not an array', enums), {
        success: false,
        configured: [],
    });
});

test('handles invalid enums parameter', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const services = ['WECAR_FLOW'];

    t.deepEqual(buildMediaEnumConfig(config, services, null), { success: false, configured: [] });
    t.deepEqual(buildMediaEnumConfig(config, services, undefined), {
        success: false,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig(config, services, 'not an object'), {
        success: false,
        configured: [],
    });
});

test('skips service not in config.media', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const services = ['WECAR_FLOW', 'XMLA_MUSIC'];
    const enums = {
        WECAR_FLOW: { service: {}, enable: false },
        XMLA_MUSIC: { service: {}, enable: false },
    };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.is(result.configured.length, 1);
    t.is(result.configured[0].serviceName, 'WECAR_FLOW');
    t.is(enums.XMLA_MUSIC.enable, false);
});

test('skips service with empty pageName', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: '' },
        },
    };
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.deepEqual(result.configured, []);
    t.is(enums.WECAR_FLOW.enable, false);
});

test('skips service with undefined pageName', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { serviceName: 'WeCarFlow' },
        },
    };
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.deepEqual(result.configured, []);
    t.is(enums.WECAR_FLOW.enable, false);
});

test('handles multiple valid services', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
            XMLA_MUSIC: { pageName: 'com.example.xmla' },
            RADIO_YUNTING: { pageName: 'com.example.radio' },
        },
    };
    const services = ['WECAR_FLOW', 'XMLA_MUSIC', 'RADIO_YUNTING'];
    const enums = {
        WECAR_FLOW: { service: {}, enable: false },
        XMLA_MUSIC: { service: {}, enable: false },
        RADIO_YUNTING: { service: {}, enable: false },
    };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.is(result.configured.length, 3);
    t.is(result.configured[0].serviceName, 'WECAR_FLOW');
    t.is(result.configured[1].serviceName, 'XMLA_MUSIC');
    t.is(result.configured[2].serviceName, 'RADIO_YUNTING');
    t.is(enums.WECAR_FLOW.enable, true);
    t.is(enums.XMLA_MUSIC.enable, true);
    t.is(enums.RADIO_YUNTING.enable, true);
});

test('handles service with only required pageName: optional fields left untouched, enable still set', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.is(result.configured.length, 1);
    t.is(result.configured[0].pageName, 'com.example.wecar');
    t.is(result.configured[0].servicePageName, undefined);
    t.is(result.configured[0].serviceName_, undefined);
    t.is(result.configured[0].clientId, undefined);

    // Optional fields must NOT be written onto the service object when absent.
    t.is(enums.WECAR_FLOW.service.pageName, 'com.example.wecar');
    t.false('servicePageName' in enums.WECAR_FLOW.service);
    t.false('serviceName' in enums.WECAR_FLOW.service);
    t.false('clientId' in enums.WECAR_FLOW.service);
    t.is(enums.WECAR_FLOW.enable, true);
});

test('handles service with partial optional fields and empty-string optional fields treated as absent', (t) => {
    const config = {
        media: {
            WECAR_FLOW: {
                pageName: 'com.example.wecar',
                serviceName: 'WeCarFlow',
                servicePageName: '',
                clientId: '',
            },
        },
    };
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.is(result.configured.length, 1);
    t.is(result.configured[0].pageName, 'com.example.wecar');
    t.is(result.configured[0].serviceName_, 'WeCarFlow');
    t.is(result.configured[0].servicePageName, '');
    t.is(result.configured[0].clientId, '');

    t.is(enums.WECAR_FLOW.service.serviceName, 'WeCarFlow');
    t.false('servicePageName' in enums.WECAR_FLOW.service);
    t.false('clientId' in enums.WECAR_FLOW.service);
});

test('handles config with extra properties, ignoring them', (t) => {
    const config = {
        media: {
            WECAR_FLOW: {
                pageName: 'com.example.wecar',
                extraProp: 'should be ignored',
            },
        },
        extraConfig: 'ignored',
    };
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.is(result.configured.length, 1);
    t.is(result.configured[0].pageName, 'com.example.wecar');
});

test('handles non-object or null service configuration entries', (t) => {
    const services = ['WECAR_FLOW'];
    const enums = { WECAR_FLOW: { service: {}, enable: false } };

    t.deepEqual(buildMediaEnumConfig({ media: { WECAR_FLOW: 'not an object' } }, services, enums), {
        success: true,
        configured: [],
    });
    t.deepEqual(buildMediaEnumConfig({ media: { WECAR_FLOW: null } }, services, enums), {
        success: true,
        configured: [],
    });
});

test('skips service missing from the enums map without touching config-derived result', (t) => {
    const config = {
        media: {
            WECAR_FLOW: { pageName: 'com.example.wecar' },
        },
    };
    const services = ['WECAR_FLOW'];
    const enums = {};

    const result = buildMediaEnumConfig(config, services, enums);

    t.is(result.success, true);
    t.deepEqual(result.configured, []);
});

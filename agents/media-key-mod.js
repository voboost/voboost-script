import { Logger } from '../lib/logger.js';
import { INFO, DEBUG, ERROR } from './media-key-mod-log.js';

import {
	MEDIA_SOURCE_CONFIG_PATH,
	loadConfig,
	parseConfig,
} from "../lib/utils.js";

const logger = new Logger("media-source-mod");

let mediaPageNames = null;

function buildPageNameMap(config) {

	const pageNameMap = {};

	if (config && config.media) {

		for (const key in config.media) {

			const entry = config.media[key];

			if (entry && typeof entry.pageName === "string" && entry.pageName.trim() !== "") {

				pageNameMap[entry.pageName] = entry;
			}
		}
	}

	return pageNameMap;
}

function handleOrientedKeyHook() {

	let EventListenerSink = Java.use("com.qinggan.keymanager.service.sinks.EventListenerSink");

	EventListenerSink.handleOrientedKey.implementation = function (i, i2) {

		try {

			let mediaRunning = this.mAudioPolicy.value.getRunningMedia();

			if (Object.prototype.hasOwnProperty.call(mediaPageNames, mediaRunning)) {
				return null;
			}

			let mediaTop = this.mAudioPolicy.value.getmTopPackageName();

			if (Object.prototype.hasOwnProperty.call(mediaPageNames, mediaTop)) {
				return null;
			}

		} catch (e) {
			logger.error(`${ERROR.HANDLE_ORIENTED_KEY} ${e}`);
			logger.error(e.stack);
		}
		return this.handleOrientedKey.call(this, i, i2);
	};
}

function init() {

	const mediaContent = loadConfig(MEDIA_SOURCE_CONFIG_PATH, logger);
	const config = parseConfig(mediaContent);
	mediaPageNames = buildPageNameMap(config);
}

function main() {

	init();
	handleOrientedKeyHook();
}

Java.perform(() => { main(); });

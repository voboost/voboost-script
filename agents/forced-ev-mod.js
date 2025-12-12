
function activeForcedEv() {

    const CanBusManager = Java.use("com.qinggan.canbus.CanBusManager");
    const VehicleState = Java.use("com.qinggan.canbus.VehicleState");

    const attemptsMax = 10;
    const delay = 800;
    let attempts = 0;

    const activate = () => {

        attempts++;

        if (attempts > attemptsMax) {

            return;
        }

        const canBusManager = CanBusManager.getInstance();

        if (canBusManager === null) {

            setTimeout(() => activate(), delay);
        }

        let result = -1;

        const currentState = canBusManager.getVehicleState(VehicleState.IVI_SOC_MODESET.value);

        if (currentState !== 5) {

            result = canBusManager.setVehicleState(VehicleState.IVI_SOC_MODESET.value, 5);

        } else {

            return;
        }

        if (result < 0) {

            setTimeout(() => activate(), delay);
        }
    };

    activate();
}

function main() {

    activeForcedEv();

    console.log("[Frida] active forced EV");
}

Java.perform(function () { main(); });

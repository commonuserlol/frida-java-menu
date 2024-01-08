namespace Menu {
    /** Waits until context become valid */
    export async function waitForInit(callback: EmptyCallback): Promise<void> {
        return new Promise((resolve, reject) => {
            const waitInterval = setInterval(() => {
                try {
                    Java.perform(() => {
                        if (!app.instance)
                            return;

                        clearInterval(waitInterval);
                        Java.scheduleOnMainThread(() => callback());
                        resolve();
                    });
                } catch (e) {}
            }, 10);
        });
    }
}
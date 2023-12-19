namespace Menu {
    export async function waitForInit(callback: EmptyCallback): Promise<void> {
        return new Promise((resolve, reject) => {
            const waitInterval = setInterval(() => {
                try {
                    if (!app.instance) return;
        
                    clearInterval(waitInterval);
                    resolve();
                    Java.perform(callback);
                } catch (e) {}
            }, 10);
        });
    }
}
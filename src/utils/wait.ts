namespace Menu {
    export async function waitForInit(callback: () => void): Promise<void> {
        return new Promise((resolve, reject) => {
            const waitInterval = setInterval(() => {
                try {
                    if (!app.instance) return;
        
                    clearInterval(waitInterval);
                    resolve();
                    console.log("hacc init");
                    Java.perform(callback);
                } catch (e) {}
            }, 10);
        });
    }
}
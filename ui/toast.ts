namespace Menu {
    /** Creates toast. Length should be 0 (2s) or 1 (3.5s) */
    export function toast(text: string, length: number) {
        Java.scheduleOnMainThread(() => Api.Toast.makeText(app.context, wrap(text), length).show());
    }
}

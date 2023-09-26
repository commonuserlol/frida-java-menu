namespace Menu {
    export function toast(text: string, length: number) {
        Java.scheduleOnMainThread(() => Api.Toast.makeText(context, wrap(text), length).show());
    }
}

namespace Menu {
    export function toast(text: string, length: number) : void {
        Java.scheduleOnMainThread(() => Api.Toast.makeText(context, wrap(text), length).show());
    }
}
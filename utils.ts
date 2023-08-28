namespace Menu {
    /** Shows toast message */
    export function toast(text: string, length: number) : void {
        Java.scheduleOnMainThread(() => Api.Toast.makeText(context, wrap(text), length).show());
    }
    /**
     * @internal Parses color from HTML format string*/
    export function parseColor(color: string): number {
        return Api.Color.parseColor(color);
    }
    /** @internal */
    export function wrap(text: string): Java.Wrapper
    {
        return Api.HTML.fromHtml(Api.JavaString.$new(String(text)));
    }
    /** @internal */
    export function dp(i: number): number {
        return Api.TypedValue.applyDimension(Api.COMPLEX_UNIT_DIP, i, context.getResources().getDisplayMetrics());
    }
    /**
     * Gets android sdk version
     *
     * @public
     * @static
     * @returns {number}
     */
    export function getApiLevel(): number {
        return Api.Build_VERSION.SDK_INT.value;
    }
    /** @internal */
    export function bitmap(icon: string): Java.Wrapper {
        const bytes = Api.Base64.decode(icon, 0);
        return Api.BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
    }
    /** @internal */
    export function checkOverlayPermission(): boolean {
        return !!Api.Settings.canDrawOverlays(context);
    }
    /** @internal */
    export function requestOverlayPermission(): void {
        const intent = Api.Intent.$new(Api.JavaString.$new("android.settings.action.MANAGE_OVERLAY_PERMISSION"));
        intent.setFlags(Api.Intent.FLAG_ACTIVITY_NEW_TASK.value);
        intent.setData(Api.Uri.parse("package:" + app.packageName));
        context.startActivity(intent);
    }
    /** Generates random string */
    export function randomString(length: number): string {
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * length));
        }
        return result;
    }
    /**
     * Formats string like `String.format` in other langs
     *
     * @public
     * @static
     * @param {String} str string which need to format, like `"Hello {0}"`
     * @param {...*} obj format args, like `"world!"`
     * @returns {string} 
     */
    export function format(str: String, ...obj: any): string {
        return str.replace(/\{\s*([^}\s]+)\s*\}/g, function(m, p1, offset, string) {
            return obj[p1]
        })
    }

    export function raise(text: string) {
        throw new Error(text);
    }

    export async function sleep(ms: number = 50) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
import { Api } from "./api.js";

/**
 * Shows toast message
 *
 * @public
 * @static
 * @param {Java.Wrapper} context 
 * @param {string | Java.Wrapper} text
 * @param {number} length 0 aka `Toast.LENGTH_SHORT` (2000ms) or 1 aka `Toast.LENGTH_LONG` (3500ms)
 */
export function toast(context: Java.Wrapper, text: string, length: number) : void {
    Java.scheduleOnMainThread(() => Api.Toast.makeText(context, wrap(text), length).show());
}
/**
 * Parses color from string
 *
 * @internal
 * @param {string} color must be `#RRGGBB` or `#AARRGGBB`
 * @returns {Java.Wrapper}
 */
export function parseColor(color: string): number {
    return Api.Color.parseColor(color);
}
/**
 * Wraps html formatted text as java object
 *
 * @public
 * @static
 * @param {string} text
 * @returns {Java.Wrapper} 
 */
export function wrap(text: string): Java.Wrapper
{
    return Api.HTML.fromHtml(Api.JavaString.$new(String(text)));
}
/**
 * Opens provided activity or link using `android.intent.action.VIEW` and `FLAG_ACTIVITY_NEW_TASK`
 *
 * @public
 * @static
 * @param {string} activity activity name or link
 * @param {Java.Wrapper} context
 */
export function openLink(activity: string, context: Java.Wrapper): void {
    const intent = Api.Intent.$new(Api.JavaString.$new("android.intent.action.VIEW"));
    intent.setFlags(Api.Intent.FLAG_ACTIVITY_NEW_TASK.value);
    intent.setData(Api.Uri.parse(activity));
    context.startActivity(intent);
}
/**
 * Converts an unpacked complex data value holding a dimension to its final floating point pixel value
 * 
 * @internal
 * @param {Java.Wrapper} context
 * @param {number} i value
 * @returns {number}
 */
export function dp(context: Java.Wrapper, i: number): number {
    return Api.TypedValue.applyDimension(Api.COMPLEX_UNIT_DIP, i, context.getResources().getDisplayMetrics());
}
/**
 * Gets android sdk version
 *
 * @public
 * @static
 * @returns {number}
 */
export function getApiVersion(): number {
    return Api.Build_VERSION.SDK_INT.value;
}
/**
 * Creates bitmap from string
 *
 * @public
 * @static
 * @param {string} icon base64 encoded string
 * @returns {Java.Wrapper}
 */
export function bitmap(icon: string): Java.Wrapper {
    const bytes = Api.Base64.decode(icon, 0);
    return Api.BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
}
/**
 * Checks if app have overlay permission
 *
 * @internal
 * @param {Java.Wrapper} context
 * @returns {boolean}
 */
export function checkOverlayPermission(context: Java.Wrapper): boolean {
    return !!Api.Settings.canDrawOverlays(context);
}
/**
 * Requests overlay permission for app
 *
 * @internal
 * @param {Java.Wrapper} context
 */
export function requestOverlayPermission(context: Java.Wrapper): void {
    const intent = Api.Intent.$new(Api.JavaString.$new("android.settings.action.MANAGE_OVERLAY_PERMISSION"));
    intent.setFlags(Api.Intent.FLAG_ACTIVITY_NEW_TASK.value);
    intent.setData(Api.Uri.parse("package:" + context.getPackageName()));
    context.startActivity(intent);
}
/**
 * Generates random js string
 *
 * @public
 * @static
 * @param {number} length
 * @returns {string}
 */
export function randomString(length: number): string {
    //https://stackoverflow.com/questions/1349404/generate-random-string-characters-in-javascript
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
    //https://stackoverflow.com/questions/2534803/use-of-string-format-in-javascript
    return str.replace(/\{\s*([^}\s]+)\s*\}/g, function(m, p1, offset, string) {
        return obj[p1]
    })
}
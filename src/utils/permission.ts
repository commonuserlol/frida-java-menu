namespace Menu {
    /** Permission interface */
    export interface Permission {
        name: string,
        ask: () => void,
        check: () => boolean
    }
    /** @internal */
    export const overlay: Permission = {
        name: "android.settings.action.MANAGE_OVERLAY_PERMISSION",
        ask() {
            toast(config.strings.noOverlayPermission, 1);
            const intent = Api.Intent.$new(Api.JavaString.$new(this.name));
            intent.setFlags(Api.Intent.FLAG_ACTIVITY_NEW_TASK.value);
            intent.setData(Api.Uri.parse("package:" + app.packageName));
            app.context.startActivity(intent);
        },
        check() {
            return !!Api.Settings.canDrawOverlays(app.context);
        }
    }
}

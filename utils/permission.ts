namespace Menu {
    export type Permission = {
        name: string,
        ask: () => void
        check: () => boolean
    }
    export const overlay: Permission = {
        name: "android.settings.action.MANAGE_OVERLAY_PERMISSION",
        ask() {
            toast(Menu.theme.noOverlayPermissionText, 1);
            const intent = Api.Intent.$new(Api.JavaString.$new("android.settings.action.MANAGE_OVERLAY_PERMISSION"));
            intent.setFlags(Api.Intent.FLAG_ACTIVITY_NEW_TASK.value);
            intent.setData(Api.Uri.parse("package:" + app.packageName));
            context.startActivity(intent);
        },
        check() {
            return !!Api.Settings.canDrawOverlays(context);
        }
    }
}
namespace Menu {
    /** @internal */
    export function dp(i: number): number {
        return Api.TypedValue.applyDimension(Api.COMPLEX_UNIT_DIP, i, context.getResources().getDisplayMetrics());
    }
    /** @internal */
    export function bitmap(icon: string): Java.Wrapper {
        const bytes = Api.Base64.decode(icon, 0);
        return Api.BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
    }
    /** @internal */
    export function parseColor(color: string): number {
        return Api.Color.parseColor(color);
    }
}
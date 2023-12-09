namespace Menu {
    export declare type ThisCallback<T extends View> = (this: T) => void;
    export declare type ThisWithIndexCallback<T extends View> = (this: T, index: number) => void;

    /** @internal */
    export function dp(i: number): number {
        return Api.TypedValue.applyDimension(Api.COMPLEX_UNIT_DIP, i, app.context.getResources().getDisplayMetrics());
    }
    /** @internal */
    export function bitmap(icon: string): Java.Wrapper {
        const bytes = Api.Base64.decode(icon, 0);
        return Api.BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
    }
    /** Parses color from #AARRGGBB or #RRGGBB */
    export function parseColor(color: string | number): number {
        return typeof color == "number" ? color : Api.Color.parseColor(`${color}`);
    }
}
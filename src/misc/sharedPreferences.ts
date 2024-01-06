namespace Menu {
    /** App's SharedPreferences storage */
    export class SharedPreferences {
        /** @internal Instance of `SharedPreferences` */
        instance: Java.Wrapper;
        
        constructor() {
            this.instance = app.context.getSharedPreferences(app.packageName + "_menuprefs", app.context.MODE_PRIVATE.value);
        }
        /** Gets string */
        getString(key: string): string {
            return this.instance.getString(Api.JavaString.$new(key), Api.JavaString.$new(""));
        }
        /** Writes string */
        putString(key: string, value: string) {
            this.instance.edit().putString(Api.JavaString.$new(key), Api.JavaString.$new(value)).apply();
        }
        /** Gets int */
        getInt(key: string): number {
            return this.instance.getInt(Api.JavaString.$new(key), -1);
        }
        /** Writes int */
        putInt(key: string, value: number) {
            this.instance.edit().putInt(Api.JavaString.$new(key), value).apply();
        }
        /** Gets float */
        getFloat(key: string): number {
            return this.instance.getFloat(Api.JavaString.$new(key), -1);
        }
        /** Writes float */
        putFloat(key: string, value: number) {
            this.instance.edit().putFloat(Api.JavaString.$new(key), value).apply();
        }
        /** Gets long */
        getLong(key: string): number {
            return this.instance.getLong(Api.JavaString.$new(key), -1);
        }
        /** Writes long */
        putLong(key: string, value: number) {
            this.instance.edit().putLong(Api.JavaString.$new(key), value).apply();
        }
        /** Gets bool */
        getBool(key: string): boolean {
            return this.instance.getBoolean(Api.JavaString.$new(key), false);
        }
        /** Writes bool */
        putBool(key: string, value: boolean) {
            this.instance.edit().putBoolean(Api.JavaString.$new(key), value).apply();
        }
        /** Is `key` inside */
        contains(key: string): boolean {
            return !!this.instance.contains(key);
        }
        /** Clears storage */
        clear(): void {
            this.instance.edit().clear().apply();
        }
    }
}

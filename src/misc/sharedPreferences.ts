namespace Menu {
    /** App's SharedPreferences storage */
    export class SharedPreferences {
        private instance: Java.Wrapper;
        
        constructor() {
            this.instance = app.context.getSharedPreferences(app.packageName + "_menuprefs", app.context.MODE_PRIVATE.value);
        }
        /** Gets string */
        public getString(key: string): string {
            return this.instance.getString(Api.JavaString.$new(key), Api.JavaString.$new(""));
        }
        /** Writes string */
        public putString(key: string, value: string) {
            this.instance.edit().putString(Api.JavaString.$new(key), Api.JavaString.$new(value)).apply();
        }
        /** Gets int */
        public getInt(key: string): number {
            return this.instance.getInt(Api.JavaString.$new(key), -1);
        }
        /** Writes int */
        public putInt(key: string, value: number) {
            this.instance.edit().putInt(Api.JavaString.$new(key), value).apply();
        }
        /** Gets float */
        public getFloat(key: string): number {
            return this.instance.getFloat(Api.JavaString.$new(key), -1);
        }
        /** Writes float */
        public putFloat(key: string, value: number) {
            this.instance.edit().putFloat(Api.JavaString.$new(key), value).apply();
        }
        /** Gets long */
        public getLong(key: string): number {
            return this.instance.getLong(Api.JavaString.$new(key), -1);
        }
        /** Writes long */
        public putLong(key: string, value: number) {
            this.instance.edit().putLong(Api.JavaString.$new(key), value).apply();
        }
        /** Gets bool */
        public getBool(key: string): boolean {
            return this.instance.getBoolean(Api.JavaString.$new(key), false);
        }
        /** Writes bool */
        public putBool(key: string, value: boolean) {
            this.instance.edit().putBoolean(Api.JavaString.$new(key), value).apply();
        }
        /** Is `key` inside */
        public contains(key: string): boolean {
            return !!this.instance.contains(key);
        }
        /** Clears storage */
        public clear(): void {
            this.instance.edit().clear().apply();
        }
    }
}

namespace Menu {
    export class SharedPreferences {
        private instance: Java.Wrapper;
        
        constructor() {
            this.instance = app.context.getSharedPreferences(app.packageName + "_menuprefs", app.context.MODE_PRIVATE.value);
        }
        /**
         * Gets string
         *
         * @internal
         * @param {string} key
         * @returns {string}
         */
        public getString(key: string): string {
            return this.instance.getString(Api.JavaString.$new(key), Api.JavaString.$new(""));
        }
        /**
         * Writes string
         *
         * @internal
         * @param {string} key
         * @param {string} value
         */
        public putString(key: string, value: string) {
            this.instance.edit().putString(Api.JavaString.$new(key), Api.JavaString.$new(value)).apply();
        }
        /**
         * Gets int
         *
         * @internal
         * @param {string} key
         * @returns {number}
         */
        public getInt(key: string): number {
            return this.instance.getInt(Api.JavaString.$new(key), -1);
        }
        /**
         * Writes int
         *
         * @internal
         * @param {string} key
         * @param {number} value
         */
        public putInt(key: string, value: number) {
            this.instance.edit().putInt(Api.JavaString.$new(key), value).apply();
        }
        /**
         * Gets float
         *
         * @internal
         * @param {string} key
         * @returns {number}
         */
        public getFloat(key: string): number {
            return this.instance.getFloat(Api.JavaString.$new(key), -1);
        }
        /**
         * Writes float
         *
         * @internal
         * @param {string} key
         * @param {number} value
         */
        public putFloat(key: string, value: number) {
            this.instance.edit().putFloat(Api.JavaString.$new(key), value).apply();
        }
        /**
         * Gets long
         *
         * @internal
         * @param {string} key
         * @returns {number}
         */
        public getLong(key: string): number {
            return this.instance.getLong(Api.JavaString.$new(key), -1);
        }
        /**
         * Writes long
         *
         * @internal
         * @param {string} key
         * @param {number} value
         */
        public putLong(key: string, value: number) {
            this.instance.edit().putLong(Api.JavaString.$new(key), value).apply();
        }
        /**
         * Gets bool
         *
         * @internal
         * @param {string} key
         * @returns {boolean}
         */
        public getBool(key: string): boolean {
            return this.instance.getBoolean(Api.JavaString.$new(key), false);
        }
        /**
         * Writes bool
         *
         * @internal
         * @param {string} key
         * @param {boolean} value
         */
        public putBool(key: string, value: boolean) {
            this.instance.edit().putBoolean(Api.JavaString.$new(key), value).apply();
        }
        /**
         * Is `key` inside in sharedprefs 
         *
         * @internal
         * @param {string} key
         * @returns {boolean}
         */
        public contains(key: string): boolean {
            return !!this.instance.contains(key);
        }
        /**
         * Clears sharedprefs storage
         *
         * @internal
         */
        public clear(): void {
            this.instance.edit().clear().apply();
        }
    }
}

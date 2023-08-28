namespace Api {
    export class SharedPreferences {
        private instance: Java.Wrapper;
        
        constructor() {
            this.instance = globalThis.Menu.context.getSharedPreferences(globalThis.Menu.app.packageName + "_menuprefs", globalThis.Menu.context.MODE_PRIVATE.value);
        }
        /**
         * Gets string
         *
         * @internal
         * @param {string} key
         * @returns {string}
         */
        public getString(key: string): string {
            return this.instance.getString(JavaString.$new(key), JavaString.$new(""));
        }
        /**
         * Writes string
         *
         * @internal
         * @param {string} key
         * @param {string} value
         */
        public putString(key: string, value: string): void {
            this.instance.edit().putString(JavaString.$new(key), JavaString.$new(value)).apply();
        }
        /**
         * Gets int
         *
         * @internal
         * @param {string} key
         * @returns {number}
         */
        public getInt(key: string): number {
            return this.instance.getInt(JavaString.$new(key), -1);
        }
        /**
         * Writes int
         *
         * @internal
         * @param {string} key
         * @param {number} value
         */
        public putInt(key: string, value: number): void {
            this.instance.edit().putInt(JavaString.$new(key), value).apply();
        }
        /**
         * Gets float
         *
         * @internal
         * @param {string} key
         * @returns {number}
         */
        public getFloat(key: string): number {
            return this.instance.getFloat(JavaString.$new(key), -1);
        }
        /**
         * Writes float
         *
         * @internal
         * @param {string} key
         * @param {number} value
         */
        public putFloat(key: string, value: number): void {
            this.instance.edit().putFloat(JavaString.$new(key), value).apply();
        }
        /**
         * Gets long
         *
         * @internal
         * @param {string} key
         * @returns {number}
         */
        public getLong(key: string): number {
            return this.instance.getLong(JavaString.$new(key), -1);
        }
        /**
         * Writes long
         *
         * @internal
         * @param {string} key
         * @param {number} value
         */
        public putLong(key: string, value: number): void {
            this.instance.edit().putLong(JavaString.$new(key), value).apply();
        }
        /**
         * Gets bool
         *
         * @internal
         * @param {string} key
         * @returns {boolean}
         */
        public getBool(key: string): boolean {
            return this.instance.getBoolean(JavaString.$new(key), false);
        }
        /**
         * Writes bool
         *
         * @internal
         * @param {string} key
         * @param {boolean} value
         */
        public putBool(key: string, value: boolean): void {
            this.instance.edit().putBoolean(JavaString.$new(key), value).apply();
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
namespace Menu {
    export class Button extends Object {
        constructor(context: Java.Wrapper, text?: string) {
            super(context);
            this.instance = Api.Button.$new(context);
            if (text) this.text = text;
        }
        /**
         * Gets is all symbols caps
         *
         * @type {boolean}
         */
        get allCaps(): boolean {
            return !!this.instance.isAllCaps();
        }
        /**
         * Sets is all symbols caps
         *
         * @type {boolean}
         */
        set allCaps(allCaps: boolean) {
            this.instance.setAllCaps(allCaps);
        }
    }
}
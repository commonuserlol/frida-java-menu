namespace Menu {
    export class Button extends Object {
        constructor(text?: string) {
            super();
            this.instance = Api.Button.$new(app.context);
            if (text) this.text = text;
        }
        /* Gets is all symbols caps */
        get allCaps(): boolean {
            return !!this.instance.isAllCaps();
        }
        /** Sets is all symbols caps */
        set allCaps(allCaps: boolean) {
            this.instance.setAllCaps(allCaps);
        }
    }
}

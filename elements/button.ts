import { Object } from "./object.js";
import { Api } from "../api.js"

/**
 * Wrapper for `Button`
 *
 * @export
 * @class Button
 * @typedef {Button}
 * @extends {Object}
 */
export class Button extends Object {
    /**
     * Creates an instance of Button.
     *
     * @constructor
     * @param {Java.Wrapper} context
     * @param {?string} [text]
     */
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
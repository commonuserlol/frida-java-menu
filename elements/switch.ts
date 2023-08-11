import { Object } from "./object.js";
import { Api } from "../api.js";
import { randomString } from "../utils.js";

/**
 * Wrapper for `Switch`
 *
 * @export
 * @class Switch
 * @typedef {Switch}
 * @extends {Object}
 */
export class Switch extends Object {
    /**
     * Creates an instance of Switch.
     *
     * @constructor
     * @param {Java.Wrapper} context
     * @param {?string} [text]
     * @param {boolean} [state=false]
     */
    constructor(context: Java.Wrapper, text?: string, state: boolean = false) {
        super(context);
        this.instance = Api.Switch.$new(context);
        if (text) this.text = text;
        this.checked = state;
    }
    /**
     * Sets checked
     *
     * @type {boolean}
     */
    set checked(checked: boolean) {
        this.instance.setChecked(checked);
    }
    /**
     * Sets onCheckedChangeListener
     *
     * @type {(state: boolean) => void}
     */
    set onCheckedChangeListener(callback: (state: boolean) => void) {
        this.instance.setOnCheckedChangeListener(Java.registerClass({
            name: randomString(35),
            implements: [Api.CompoundButton_OnCheckedChangeListener],
            methods: {
                onCheckedChanged: (object: Java.Wrapper, state: boolean) => {
                    callback(state);
                }
            }
        }).$new());
    }
}
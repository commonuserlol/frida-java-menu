namespace Menu {
    /**
     * Wrapper class for `AlertDialog(.Builder)`
     *
     * @export
     * @class Dialog
     * @typedef {Dialog}
     * @extends {Object}
     */
    export class Dialog extends Object {

        /**
         * Creates an instance of Dialog.
         *
         * @constructor
         * @param {Java.Wrapper} context
         * @param {?string} [title]
         * @param {?string} [message]
         */
        constructor(context: Java.Wrapper, title?: string, message?: string) {
            super(context);
            this.instance = Api.AlertDialog_Builder.$new(context);
            if (title) this.title = title;
            if (message) this.message = message;
        }
        /**
         * Sets title
         *
         * @type {string}
         */
        set title(title: string) {
            this.instance.setTitle(wrap(title));
        }
        /**
         * Sets message
         *
         * @type {string}
         */
        set message(message: string) {
            this.instance.setMessage(wrap(message));
        }
        /**
         * Sets view
         *
         * @type {*}
         */
        set view(view: Java.Wrapper) {
            this.instance.setView(view);
        }
        /**
         * Sets positive button
         *
         * @public
         * @param {string} text button text
         * @param {() => void} callback
         */
        public setPositiveButton(text: string, callback: () => void) {
            this.instance.setPositiveButton(wrap(text), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerPositive";
                    },
                    onClick: (dialog: Java.Wrapper, which: Java.Wrapper) => {
                        callback();
                    }
                }
            }).$new());
        }
        /**
         * Sets negative button
         *
         * @public
         * @param {string} text button text
         * @param {() => void} callback
         */
        public setNegativeButton(text: string, callback: () => void) {
            this.instance.setNegativeButton(wrap(text), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerNegative";
                    },
                    onClick: (dialog, which) => {
                        callback();
                    }
                }
            }).$new());
        }
        /**
         * Shows dialog
         *
         * @public
         */
        public show() {
            const dialog = this.instance.create();
            dialog.getWindow().setType(getApiVersion() >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value);
            dialog.show();
        }
    }
}
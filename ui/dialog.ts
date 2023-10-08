namespace Menu {
    export class Dialog extends Object {
        constructor(context: Java.Wrapper, title?: string, message?: string) {
            super(context);
            this.instance = Api.AlertDialog_Builder.$new(context);
            if (title) this.title = title;
            if (message) this.message = message;
        }
        /** Sets title */
        set title(title: string) {
            this.instance.setTitle(wrap(title));
        }
        /** Sets message */
        set message(message: string) {
            this.instance.setMessage(wrap(message));
        }
        /** Sets view */
        set view(view: Java.Wrapper) {
            this.instance.setView(view);
        }
        /** Sets positive button */
        public setPositiveButton(callback: (this: Dialog) => void) {
            this.instance.setPositiveButton(wrap(theme.dialogPositiveText), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerPositive";
                    },
                    onClick: (dialog: Java.Wrapper, which: Java.Wrapper) => {
                        callback.call(this);
                    }
                }
            }).$new());
        }
        /** Sets negative button */
        public setNegativeButton(callback: (this: Dialog) => void) {
            this.instance.setNegativeButton(wrap(theme.dialogNegativeText), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerNegative";
                    },
                    onClick: () => callback.call(this)
                }
            }).$new());
        }
        /** Shows dialog */
        public show() {
            const dialog = this.instance.create();
            dialog.getWindow().setType(apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value);
            dialog.show();
        }
    }
}
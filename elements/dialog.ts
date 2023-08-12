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
            this.instance.setPositiveButton(wrap(Menu.getInstance().theme.dialogPositiveText), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerPositive";
                    },
                    onClick: (dialog: Java.Wrapper, which: Java.Wrapper) => {
                        callback.bind(this)();
                    }
                }
            }).$new());
        }
        /** Sets negative button */
        public setNegativeButton(callback: (this: Dialog) => void) {
            this.instance.setNegativeButton(wrap(Menu.getInstance().theme.dialogNegativeText), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerNegative";
                    },
                    onClick: (dialog, which) => {
                        callback.bind(this)();
                    }
                }
            }).$new());
        }
        /** Shows dialog */
        public show() {
            const dialog = this.instance.create();
            dialog.getWindow().setType(getApiLevel() >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value);
            dialog.show();
        }
    }

    export async function dialog(title: string, message: string, positiveButton?: (this: Dialog) => void, negativeButton?: (this: Dialog) => void, view?: Java.Wrapper | Object): Promise<Dialog> {
        //We can create a dialog only with an activity instance, the context is not suitable.
        const instance = await Api.MainActivity.instance.getClassInstance();
        const dialog = new Dialog(instance, title, message);
        view ? (view instanceof Object ? dialog.view = view.instance : dialog.view = view) : null;
        if (positiveButton) dialog.setPositiveButton(positiveButton)
        if (negativeButton) dialog.setNegativeButton(negativeButton);

        return dialog;
    }
}
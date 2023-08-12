namespace Menu {
    export type OnClickListener = {
        label: string,
        callback: () => void
    }

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
        public setPositiveButton(button: OnClickListener) {
            this.instance.setPositiveButton(wrap(button.label), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerPositive";
                    },
                    onClick: (dialog: Java.Wrapper, which: Java.Wrapper) => {
                        button.callback();
                    }
                }
            }).$new());
        }
        /** Sets negative button */
        public setNegativeButton(button: OnClickListener) {
            this.instance.setNegativeButton(wrap(button.label), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerNegative";
                    },
                    onClick: (dialog, which) => {
                        button.callback();
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

    export function dialog(context: Java.Wrapper, title: string, message: string, positiveButton?: OnClickListener, negativeButton?: OnClickListener, view?: Java.Wrapper | Object): Dialog {
        const dialog = new Dialog(context, title, message);
        view ? (view instanceof Object ? dialog.view = view.instance : dialog.view = view) : null;
        if (positiveButton) dialog.setPositiveButton(positiveButton)
        if (negativeButton) dialog.setNegativeButton(negativeButton);

        return dialog;
    }
}
namespace Menu {
    export declare type DialogCallback = {
        label: string,
        fn: (this: Dialog) => void
    };

    export declare type DialogInputCallback<T extends string | number> = {
        label: string,
        fn: (this: Dialog, result: T) => void
    }

    export class Dialog extends View {
        constructor(context: Java.Wrapper, title?: string, message?: string) {
            super();
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
        public setPositiveButton(callback: DialogCallback) {
            this.instance.setPositiveButton(wrap(callback.label), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerPositive";
                    },
                    onClick: (dialog: Java.Wrapper, which: Java.Wrapper) => {
                        callback.fn.call(this);
                    }
                }
            }).$new());
        }
        /** Sets negative button */
        public setNegativeButton(callback: DialogCallback) {
            this.instance.setNegativeButton(wrap(callback.label), Java.registerClass({
                name: randomString(35),
                implements: [Api.DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return "OnClickListenerNegative";
                    },
                    onClick: () => callback.fn.call(this)
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

namespace Menu {
    export declare type DialogCallback = {
        /** Callback label */
        label: string,
        /** JS callback function */
        fn: (this: Dialog) => void
    };

    export declare type DialogInputCallback<T extends string | number> = {
        /** Callback label */
        label: string,
        /** JS callback function */
        fn: (this: Dialog, result: T) => void
    }

    /** Wrapper for `android.app.AlertDialog(.Builder)` */
    export class Dialog extends View {
        constructor(context: Java.Wrapper, title?: string, message?: string) {
            super();
            this.instance = Api.AlertDialog_Builder.$new(context);
            if (title)
                this.title = title;
            if (message)
                this.message = message;
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
        setPositiveButton(callback: DialogCallback) {
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
        setNegativeButton(callback: DialogCallback) {
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
        /** Creates dialog */
        create() {
            return this.instance.create();
        }

        /** Shows dialog */
        show(): void;
        /** Shows dialog with given instance by `create` method call */
        show(instance: Java.Wrapper): void;
        /** @internal */
        show(instance?: Java.Wrapper) {
            const dialog = instance ?? this.create();
            dialog.getWindow().setType(apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value);
            dialog.show();
        }
    }

    /** @internal Initializes new `android.app.AlertDialog(.Builder)` wrapper with default parameters */
    export async function dialog(title: string, message: string, positiveCallback?: DialogCallback, negativeCallback?: DialogCallback, view?: Java.Wrapper | View): Promise<Dialog> {
        const dialog = new Dialog(await activityInstance, title, message);
        view ? (view instanceof View ? dialog.view = view.instance : dialog.view = view) : null;
        if (positiveCallback)
            dialog.setPositiveButton(positiveCallback)
        if (negativeCallback)
            dialog.setNegativeButton(negativeCallback);

        return dialog;
    }
}

namespace Menu {
    export declare type ComposerHandler = (view: View, layout?: Java.Wrapper | View) => void;

    /** Generic class for templates. Your template must extend this */
    export abstract class GenericLayout {
        /** Menu props */
        params: Java.Wrapper; // TODO: Maybe i should add wrapper for *params
        /** Layout as layout */
        me: Layout;
        /** Proxy layout for scrolling feature */
        proxy: Layout;
        /** Main layout for widgets */
        layout: Layout;
        /** Layout for title and settings */
        titleLayout: Layout;
        /** Title TextView */
        title: TextView;
        /** Subtitle TextView */
        subtitle: TextView;
        /** Layout for hide/kill and close buttons */
        buttonLayout: Layout;
        /** Hide/kill button */
        hide: Button;
        /** Close button */
        close: Button;

        constructor(cfg: GenericConfig) {
            config = cfg;
        }

        /** Initializes menu props */
        initializeParams(): void {
            this.params = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, apiLevel >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3);
        };

        /** Initializes own layout */
        abstract initializeLayout(): void;

        /** Sets icon style */
        abstract initializeIcon(): void;

        /** Initializes proxy layout for scrolling feature */
        initializeProxy(): void {
            this.proxy = new Layout(Api.ScrollView);
        };

        /** Initializes main layout for widgets */
        abstract initializeMainLayout(): void;

        /** Initializes hide/kill & close button and their layout */
        abstract initializeButtons(): void;

        /** Initializes everything needed for start
         * 
         * Called by constructor after title & subtitle init
         */
        abstract ensureInitialized(): void;

        /** Adds everything needed from template */
        abstract handleAdd(add: ComposerHandler): void;

        /** Removes template objects */
        abstract handleRemove(remove: ComposerHandler): void;

        abstract button(label: string, callback?: ThisCallback<Button>, longCallback?: ThisCallback<Button>): Button;

        abstract dialog(title: string, message: string, positiveCallback?: DialogCallback, negativeCallback?: DialogCallback, view?: Java.Wrapper | View): Promise<Dialog>;

        abstract radioGroup(label: string, buttons: string[], callback?: ThisWithIndexCallback<Button>): RadioGroup;

        abstract seekbar(label: string, max: number, min?: number, callback?: SeekBarCallback): View;

        abstract spinner(items: string[], callback?: ThisWithIndexCallback<Spinner>): Spinner;

        abstract toggle(label: string, callback?: SwitchCallback): Switch;

        abstract textView(label: string): TextView;

        async inputNumber(title: string, max: number, positiveCallback: DialogInputCallback<number>, negativeCallback: DialogCallback): Promise<Dialog> {
            const view = Api.EditText.$new(app.context);
            if (max > 0) {
                view.setHint(Api.JavaString.$new(`Max value: ${max}`));
            }
            view.setInputType(Api.InputType.TYPE_CLASS_NUMBER.value);

            return await this.dialog(title, "", {
                label: positiveCallback?.label,
                fn: function () {
                    const result = parseFloat(Java.cast(view, Api.TextView).getText().toString());
                    !Number.isNaN(result) ? positiveCallback?.fn.call(this, result <= max ? result : max) : positiveCallback?.fn.call(this, NaN);
                },
            },
            negativeCallback, view);
        }

        async inputText(title: string, positiveCallback: DialogInputCallback<string>, negativeCallback: DialogCallback, hint?: string): Promise<Dialog> {
            const view = Api.EditText.$new(app.context);
            if (hint) view.setHint(wrap(hint));
            return await this.dialog(title, "", {
                label: positiveCallback.label,
                fn: function () {
                    const result = Java.cast(view, Api.TextView).getText().toString();
                    positiveCallback?.fn.call(this, result);
                }
            }, negativeCallback, view);
        }

        abstract destroy(): void;
    }
}
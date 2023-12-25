namespace Menu {
    /** Wrapper for `android.widget.Spinner` */
    export class Spinner extends View {
        /** Java `ArrayList` with items */
        items: Java.Wrapper;
        /** @internal Workaround to skip self-call for callback */
        initialized: boolean;

        constructor(items: string[]) {
            super();
            this.instance = Api.Spinner.$new(app.context);
            this.items = Api.ArrayList.$new(Api.Arrays.asList(Java.array("java.lang.String", items)));
            this.initialized = false;

            const arrayAdapter = Api.ArrayAdapter.$new(app.context, Api.simple_spinner_dropdown_item, this.items);
            arrayAdapter.setDropDownViewResource(Api.simple_spinner_dropdown_item);
            this.adapter = arrayAdapter;
        }
        /** Gets adapter */
        get adapter(): Java.Wrapper {
            return this.instance.getAdapter();
        }
        /** Gets current selection index */
        get selection(): number {
            return this.items.indexOf(this.instance.getSelectedView());
        }
        /** Sets adapter */
        set adapter(adapter: Java.Wrapper) {
            this.instance.setAdapter(adapter);
        }
        /** Sets onItemSelectedListener */
        set onItemSelectedListener(callback: ThisWithIndexCallback<Spinner>) {
            this.instance.setOnItemSelectedListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnItemSelectedListener],
                methods: {
                    onItemSelected: (parent: Java.Wrapper, selected: Java.Wrapper, index: number, id: number) => {
                        if (!this.initialized) {
                            this.initialized = true;
                            return;
                        };
                        sharedPreferences.putInt(Api.JavaString.join(Api.JavaString.$new(", "), this.items), index);
                        new View(parent.getChildAt(0)).textColor = config.color.secondaryText; // gc will kill it (ig)
                        callback.call(this, index);
                    },
                    onNothingSelected: function(parent: Java.Wrapper) {

                    }
                }
            }).$new());
        }
        /** Sets selection by given index */
        set selection(position: number) {
            this.instance.setSelection(position);
        }
    }

    /** @internal Initializes new `android.widget.Spinner` wrapper with default parameters */
    export function spinner(items: string[], callback?: ThisWithIndexCallback<Spinner>): Spinner {
        const spinner = new Spinner(items);
        if (callback)
            spinner.onItemSelectedListener = callback;

        const savedIndex = sharedPreferences.getInt(items.join());
        if (savedIndex > -1)
            Java.scheduleOnMainThread(() => spinner.selection = savedIndex);

        return spinner;
    }
}

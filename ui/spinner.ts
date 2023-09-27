namespace Menu {
    export class Spinner extends Object {
        private theme: Theme;
        public items: Java.Wrapper;

        constructor(items: string[], theme: Theme) {
            super(context);
            this.instance = Api.Spinner.$new(context);
            this.theme = theme;
            this.items = Api.ArrayList.$new(Api.Arrays.asList(Java.array("java.lang.String", items)));
            let params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.WRAP_CONTENT);
            params.setMargins(7, 2, 7, 2);
            this.layoutParams = params;
            this.background.setColorFilter(1, Api.Mode.SRC_ATOP.value);
            let arrayAdapter = Api.ArrayAdapter.$new(this.context, Api.simple_spinner_dropdown_item, this.items);
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
        set onItemSelectedListener(callback: (index: number) => void) {
            this.instance.setOnItemSelectedListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnItemSelectedListener],
                methods: {
                    onItemSelected: (parent: Java.Wrapper, selected: Java.Wrapper, index: number, id: number) => {
                        Java.cast(parent.getChildAt(0), Api.TextView).setTextColor(this.theme.secondaryTextColor);
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
}

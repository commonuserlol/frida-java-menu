namespace Menu {
    export class SeekBar extends Object {
        public readonly label: TextView;
        public unformattedText: String;

        constructor(context: Java.Wrapper, text: string, progress: number = 0) {
            super(context);
            this.instance = Api.SeekBar.$new(context);
            this.unformattedText = new String(text);
            this.label = new TextView(context, format(this.unformattedText, progress ?? 0));
            this.progress = progress;
        }
        /** Gets max value */
        get max(): number {
            return this.instance.getMax();
        }
        /** Gets min value */
        get min(): number {
            return this.instance.getMin();
        }
        /** Gets progress */
        get progress(): number {
            return this.instance.getProgress();
        }
        /** Sets max value */
        set max(max: number) {
            this.instance.setMax(max);
        }
        /** Sets min value */
        set min(min: number) {
            try {
                if (this.progress < min) {
                    this.progress = min;
                    this.instance.setMin(min);
                }
            }
            catch (e) {
                raise("App running on android lower than 8; set min value failed");
            }
        }
        /** Sets onSeekBarChangeListener callback */
        set onSeekBarChangeListener(callback: (progress: number) => void) {
            this.instance.setOnSeekBarChangeListener(Java.registerClass({
                name: randomString(35),
                implements: [Api.OnSeekBarChangeListener],
                methods: {
                    onStartTrackingTouch: function(seekBar: Java.Wrapper) {

                    },
                    onStopTrackingTouch: function(seekBar: Java.Wrapper) {

                    },
                    onProgressChanged: (seekBar: Java.Wrapper, progress: number) => {
                        seekBar.setProgress(progress)
                        this.label.text = format(this.unformattedText, progress);
                        callback(progress);
                    }
                }
            }).$new());
        }
        /** Sets progress */
        set progress(progress: number) {
            this.label.text = format(this.unformattedText, progress);
            this.instance.setProgress(progress);
        }
    }

    export function seekbar(context: Java.Wrapper, label: string, max: number, min?: number, callback?: (this: SeekBar, progress: number) => void): SeekBar {
        const seekbar = new SeekBar(context, label, Menu.getInstance().sharedPrefs.getInt(label));
        const layout = new Object(context);
        layout.instance = Api.LinearLayout.$new(context);
        layout.layoutParams = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
        seekbar.padding = [25, 10, 35, 10];
        seekbar.max = max;
        min ? seekbar.min = min : seekbar.min = 0;
        if (callback) seekbar.onSeekBarChangeListener = callback?.bind(seekbar);
        
    }
}
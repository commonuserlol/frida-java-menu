import * as Utils from "./utils.js";
import { Theme } from "./theme.js";
import { Api, OnTouch, MainActivity, SharedPreferences } from "./api.js";
import { Button, Dialog, Object, RadioGroup, SeekBar, Spinner, Switch, TextView } from "./elements.js";

/**
 * Main menu class
 *
 * @export
 * @class Menu
 * @typedef {Menu}
 */
export class Menu {
    private static instance: Menu;
    private layout: Java.Wrapper;
    private rootFrame: Java.Wrapper;
    private rootContainer: Java.Wrapper;
    private expandedView: Java.Wrapper;
    private menuParams: Java.Wrapper;
    private iconView: Object;
    private collapsedView: Java.Wrapper;
    private titleLayout: Java.Wrapper;
    private settingsView: Java.Wrapper;
    private scrollView: Java.Wrapper;
    private sharedPrefs: SharedPreferences;
    private isAlive: boolean;
    public context: Java.Wrapper;
    public theme: Theme;
    public windowManager: Java.Wrapper;

    /**
     * Creates an instance of Menu.
     *
     * @constructor
     * @param {string} title
     * @param {string} subtitle
     * @param {Theme} theme
     */
    constructor (title: string, subtitle: string, theme: Theme) {
        Menu.instance = this;
        this.context = Api.ActivityThread.currentApplication().getApplicationContext();
        this.theme = theme;
        this.isAlive = true;
        if (!Utils.checkOverlayPermission(this.context)) {
            Utils.toast(this.context, this.theme.noOverlayPermissionText, 1);
            Utils.requestOverlayPermission(this.context);
            throw Error("No permission provided! Aborting...");
        }
        this.sharedPrefs = new SharedPreferences(this.context);
        this.windowManager = Java.retain(Java.cast(this.context.getSystemService(Api.WINDOW_SERVICE), Api.ViewManager));
        this.rootFrame = Api.FrameLayout.$new(this.context);
        this.rootContainer = Api.RelativeLayout.$new(this.context);
        this.menuParams = Api.WindowManager_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT, Utils.getApiVersion() >= 26 ? Api.WindowManager_Params.TYPE_APPLICATION_OVERLAY.value : Api.WindowManager_Params.TYPE_PHONE.value, 8, -3); 
        this.collapsedView = Api.RelativeLayout.$new(this.context);
        this.expandedView = Api.LinearLayout.$new(this.context);
        this.layout = Api.LinearLayout.$new(this.context);
        this.titleLayout = Api.RelativeLayout.$new(this.context);
        this.scrollView = Api.ScrollView.$new(this.context);
        let titleText = new TextView(this.context, title);
        let titleParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
        let subtitleText = new TextView(this.context, subtitle);
        let scrollParams = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Math.floor(Utils.dp(this.context, this.theme.menuHeight)));
        let buttonView = Api.RelativeLayout.$new(this.context);
        let hideButtonParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
        let hideButton = new Button(this.context);
        let closeButtonParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
        let closeButton = new Button(this.context);
        
        this.menuParams.gravity.value = 51;
        this.menuParams.x.value = this.theme.menuXPosition;
        this.menuParams.y.value = this.theme.menuYPosition;
        
        this.collapsedView.setVisibility(Api.VISIBLE);
        this.collapsedView.setAlpha(this.theme.iconAlpha);
        
        this.expandedView.setVisibility(Api.GONE);
        this.expandedView.setBackgroundColor(this.theme.bgColor);
        this.expandedView.setOrientation(Api.VERTICAL);
        this.expandedView.setLayoutParams(Api.LinearLayout_Params.$new(Math.floor(Utils.dp(this.context, this.theme.menuWidth)), Api.WRAP_CONTENT));
        
        this.titleLayout.setPadding(10, 5, 10, 5);
        this.titleLayout.setVerticalGravity(16);
        
        titleText.textColor = this.theme.primaryTextColor;
        titleText.textSize = 18;
        titleText.gravity = Api.CENTER;
        
        titleParams.addRule(Api.CENTER_HORIZONTAL);
        titleText.layoutParams = titleParams;
        
        subtitleText.ellipsize = Api.TruncateAt.MARQUEE.value;
        subtitleText.marqueeRepeatLimit = -1;
        subtitleText.singleLine = true;
        subtitleText.selected = true;
        subtitleText.textColor = this.theme.primaryTextColor;
        subtitleText.textSize = 10;
        subtitleText.gravity = Api.CENTER;
        subtitleText.padding = [0, 0, 0, 5];
        
        this.scrollView.setLayoutParams(scrollParams);
        this.scrollView.setBackgroundColor(this.theme.layoutColor);
        this.layout.setOrientation(Api.VERTICAL);
        
        buttonView.setPadding(10, 3, 10, 3);
        buttonView.setVerticalGravity(Api.CENTER);
        
        hideButtonParams.addRule(Api.ALIGN_PARENT_LEFT);
        hideButton.layoutParams = hideButtonParams;
        hideButton.backgroundColor = Api.TRANSPARENT;
        hideButton.text = this.theme.hideButtonText;
        hideButton.textColor = this.theme.primaryTextColor;
        hideButton.onClickListener = () => {
            this.collapsedView.setVisibility(Api.VISIBLE);
            this.collapsedView.setAlpha(0);
            this.expandedView.setVisibility(Api.GONE);
            Utils.toast(this.context, this.theme.iconHiddenText, 1);
        }
        hideButton.onLongClickListener = () => {
            this.destroy();
            this.isAlive = false;
            Utils.toast(this.context, this.theme.killText, 1);
            MainActivity.instance.onPause = null;
            MainActivity.instance.onResume = null;
            MainActivity.instance.onDestroy = null;
        }

        closeButtonParams.addRule(Api.ALIGN_PARENT_RIGHT);
        closeButton.layoutParams = closeButtonParams;
        closeButton.backgroundColor = 0;
        closeButton.text = this.theme.closeText;
        closeButton.textColor = this.theme.primaryTextColor;
        closeButton.onClickListener = () => {
            this.collapsedView.setVisibility(Api.VISIBLE);
            this.collapsedView.setAlpha(this.theme.iconAlpha);
            this.expandedView.setVisibility(Api.GONE);
        }

        new OnTouch(this.windowManager, this.collapsedView, this.expandedView, this.rootFrame, this.menuParams).setUser(this.rootFrame);
        
        this.add(this.collapsedView, this.rootContainer);
        this.add(this.expandedView, this.rootContainer);
        this.add(titleText, this.titleLayout);
        this.add(this.titleLayout, this.expandedView);
        this.add(subtitleText, this.expandedView);
        this.add(this.layout, this.scrollView);
        this.add(this.scrollView, this.expandedView);
        this.add(hideButton, buttonView);
        this.add(closeButton, buttonView);
        this.add(buttonView, this.expandedView);

        MainActivity.instance.onDestroy = () => {
            this.destroy();
        };
        MainActivity.instance.onPause = () => {
            this.destroy();
        };
        MainActivity.instance.onResume = () => {
            this.show();
        };
    }

    /**
     * Sets icon for menu
     *
     * @public
     * @param {string} value can be base64-encoded image or link (only for Web type)
     * @param {("Normal" | "Web")} [type="Normal"] Normal accepts only base64-encoded image. Web accepts links to images/gifs, etc
     */
    public icon(value: string, type: "Normal" | "Web" = "Normal"): void {
        Java.scheduleOnMainThread(() => {
            this.iconView = new Object(this.context);
            switch (type) {
                case "Normal":
                    this.iconView.instance = Api.ImageView.$new(this.context);
                    this.iconView.instance.setScaleType(Api.ScaleType.FIT_XY.value);
                    this.iconView.onClickListener = () => {
                        this.collapsedView.setVisibility(Api.GONE);
                        this.expandedView.setVisibility(Api.VISIBLE);
                    }
                    this.iconView.instance.setImageBitmap(Utils.bitmap(value));
                    break;
                case "Web":
                    this.iconView.instance = Api.WebView.$new(this.context);
                    this.iconView.instance.loadData(`<html><head></head><body style=\"margin: 0; padding: 0\"><img src=\"${value}\" width=\"${this.theme.iconSize}\" height=\"${this.theme.iconSize}\" ></body></html>`, "text/html", "utf-8");
                    this.iconView.backgroundColor = Api.TRANSPARENT;
                    this.iconView.instance.setAlpha(this.theme.iconAlpha);
                    this.iconView.instance.getSettings().setAppCacheEnabled(true);
                    break;
                default:
                    throw Error("Unsupported icon type!");
            }
            this.iconView.layoutParams = Api.LinearLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            let applyDimension = Math.floor(Utils.dp(this.context, this.theme.iconSize));
            this.iconView.instance.getLayoutParams().height.value = applyDimension;
            this.iconView.instance.getLayoutParams().width.value = applyDimension;
            new OnTouch(this.windowManager, this.collapsedView, this.expandedView, this.rootFrame, this.menuParams).setUser(this.iconView.instance);
            
            this.add(this.iconView, this.collapsedView);
        });
    }

    /**
     * Sets menu settings
     *
     * @public
     * @param {string} text 
     * @param {boolean} state
     * @returns {Java.Wrapper}
     */
    public settings(text: string, state: boolean): Java.Wrapper {
        let settings = new TextView(this.context, text);
        this.settingsView = Api.LinearLayout.$new(this.context);
        this.settingsView.setOrientation(Api.VERTICAL);
        settings.textColor = this.theme.primaryTextColor;
        settings.typeface = Api.Typeface.DEFAULT_BOLD.value;
        settings.textSize = 20;
        let settingsParams = Api.RelativeLayout_Params.$new(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
        settingsParams.addRule(Api.ALIGN_PARENT_RIGHT);
        settings.layoutParams = settingsParams;
        settings.onClickListener = () => {
            state = !state;
            if (state) {
                this.remove(this.layout, this.scrollView);
                this.add(this.settingsView, this.scrollView);
            }
            else {
                this.remove(this.settingsView, this.scrollView);
                this.add(this.layout, this.scrollView);
            }
        }
        this.add(settings, this.titleLayout);
        return this.settingsView;
    }

    /**
     * Destroys menu
     *
     * @public
     */
    public destroy(): void {
        Java.scheduleOnMainThread(() => {
            try {
                this.remove(this.rootContainer, this.rootFrame);
                this.rootFrame.setVisibility(Api.GONE);
                this.remove(this.rootFrame, this.windowManager);
            }
            catch (e) {
                console.warn("Menu already destroyed, ignoring `destroy` call");
            }
        });
    }

    /**
     * Shows menu
     *
     * @public
     */
    public show(): void {
        Java.scheduleOnMainThread(() => {
            if (!this.isAlive) return;
            try {
                this.windowManager.addView(this.rootFrame, this.menuParams);
                this.add(this.rootContainer, this.rootFrame);
                this.rootFrame.setVisibility(Api.VISIBLE);
            }
            catch (e) {
                console.warn("Menu already showed, ignoring `show` call");
            }
        });
    }

    /**
     * Adds view to layout
     *
     * @public
     * @param {(Java.Wrapper | Object)} view to add
     * @param {?Java.Wrapper} [layout] for add. If not provided general layout will be used
     */
    public add(view: Java.Wrapper | Object, layout?: Java.Wrapper): void {
        Java.scheduleOnMainThread(() => {
            (layout ?? this.layout)?.addView((view instanceof Object ? view.instance : view));
        })
    }

    /**
     * Removes view from layout
     *
     * @public
     * @param {(Java.Wrapper | Object)} view to remove
     * @param {?Java.Wrapper} [layout] for remove. If not provided general layout will be used
     */
    public remove(view: Java.Wrapper | Object, layout?: Java.Wrapper): void {
        Java.scheduleOnMainThread(() => {
            (layout ?? this.layout)?.removeView((view instanceof Object ? view.instance : view));
        })
    }

    /**
     * Creates label
     *
     * @public
     * @param {string} text
     * @returns {TextView}
     */
    public label(text: string): TextView {
        let label = new TextView(this.context, text);
        label.textColor = this.theme.secondaryTextColor;
        label.padding = [10, 5, 10, 5];
        return label;
    }

    /**
     * Creates button
     *
     * @public
     * @param {string} text
     * @param {?(thiz: Button) => void} [callback]
     * @returns {Button}
     */
    public button(text: string, callback?: (this: Button) => void): Button {
        let button = new Button(this.context, text);
        let params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
        params.setMargins(7, 5, 7, 5);
        button.layoutParams = params;
        button.allCaps = false;
        button.textColor = this.theme.secondaryTextColor;
        button.backgroundColor = this.theme.buttonColor;
        if (callback) button.onClickListener = () => callback.call(button);
        return button;
    }

    /**
     * Creates toggle
     *
     * @public
     * @param {string} text
     * @param {?(state: boolean) => void} [callback]
     * @returns {Switch}
     */
    public toggle(text: string, callback?: (this: Switch, state: boolean) => void): Switch {
        let toggle = new Switch(this.context, text);
        toggle.text = text;
        toggle.textColor = this.theme.secondaryTextColor;
        toggle.padding = [10, 5, 10, 5];
        toggle.onCheckedChangeListener = (state: boolean) => {
            this.sharedPrefs.putBool(text, state);
            callback?.call(toggle, state);
        }
        if (this.sharedPrefs.getBool(text)) Java.scheduleOnMainThread(() => toggle.checked = true);
        return toggle;
    }

    /**
     * Creates radio group
     *
     * @public
     * @param {string} text unformatted text (e.g `"Pressed: {0}"`)
     * @param {string[]} buttonLabels 
     * @param {?(index: number) => void} [callback]
     * @returns {RadioGroup}
     */
    public radioButtons(text: string, buttonLabels: string[], callback?: (this: RadioGroup, index: number) => void): RadioGroup {
        let group = new RadioGroup(this.context, text, this.theme);
        group.padding = [10, 5, 10, 5];
        group.orientation = 1;
        for (let i = 0; i<buttonLabels.length; i++) {
            group.addButton(buttonLabels[i], i, (index: number) => {
                this.sharedPrefs.putInt(text, index);
                callback?.call(group, i);
            });
        }
        let index = this.sharedPrefs.getInt(text);
        if (index != -1) group.check(group.getChildAt(index+1).getId());
        return group;
    }

    /**
     * Creates slider
     *
     * @public
     * @param {string} text unformatted text (e.g. `"Progress: {0}"`)
     * @param {number} max 
     * @param {?number} [min] will be ignored if android version is < 8
     * @param {?(progress: number) => void} [callback]
     * @returns {Java.Wrapper}
     */
    public slider(text: string, max: number, min?: number, callback?: (this: SeekBar, progress: number) => void): Java.Wrapper {
        let seekBar = new SeekBar(this.context, text, min);
        let layout = Api.LinearLayout.$new(this.context);
        let params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
        layout.setLayoutParams(params);
        layout.setOrientation(Api.VERTICAL);
        seekBar.padding = [25, 10, 35, 10];
        seekBar.max = max;
        min ? seekBar.min = min : seekBar.min = 0;
        seekBar.onSeekBarChangeListener = (progress: number) => {
            this.sharedPrefs.putInt(text, progress);
            callback?.call(seekBar, progress);
        }
        this.add(seekBar.label, layout);
        this.add(seekBar, layout);
        let progress = this.sharedPrefs.getInt(text);
        if (progress != -1) seekBar.progress = progress;
        return layout;
    }

    /**
     * Creates spinner
     *
     * @public
     * @param {string[]} items
     * @param {?(index: number) => void} [callback]
     * @returns {Spinner}
     */
    public spinner(items: string[], callback?: (this: Spinner, index: number) => void): Spinner {
        let spinner = new Spinner(this.context, items, this.theme);
        spinner.onItemSelectedListener = (index: number) => {
            this.sharedPrefs.putInt(items.join(), index);
            callback?.call(spinner, index);
        }
        let index = this.sharedPrefs.getInt(items.join());
        if (index != -1) Java.scheduleOnMainThread(() => spinner.selection = index);
        return spinner;
    }

    /**
     * Creates category
     *
     * @public
     * @param {string} text
     * @returns {TextView}
     */
    public category(text: string): TextView {
        let label = this.label(text);
        label.backgroundColor = this.theme.categoryColor;
        label.gravity = Api.CENTER;
        label.padding = [0, 5, 0, 5];
        label.typeface = Api.Typeface.DEFAULT_BOLD.value;
        return label;
    }

    /**
     * Creates dialog
     *
     * @public
     * @param {string} title
     * @param {string} message
     * @param {(isSuccessful: boolean) => void} callback
     * @param {?Java.Wrapper} [view] view to add into layout
     */
    public dialog(title: string, message: string, callback: (this: Dialog, isSuccessful: boolean) => void, view?: Java.Wrapper) {
        MainActivity.instance.getClassInstance().then((instance) => {
            let dialog = new Dialog(instance, title, message);
            dialog.setPositiveButton(this.theme.dialogPositiveText, () => {
                callback?.call(dialog, true);
            });
            dialog.setNegativeButton(this.theme.dialogNegativeText, () => {
                callback?.call(dialog, false);
            });
            if (view) dialog.view = view;
            dialog.show();
        });
    }

    /**
     * Creates dialog with input number
     *
     * @public
     * @param {string} title
     * @param {number} max 
     * @param {?(isSuccessful: boolean, result?: number) => void} [callback]
     */
    public inputNumber(title: string, max: number, callback?: (this: Dialog, isSuccessful: boolean, result?: number) => void): void {
        let view = Api.EditText.$new(this.context);
        if (max > 0) {
            view.setHint(Api.JavaString.$new(`Max value: ${max}`));
        }
        view.setInputType(Api.InputType.TYPE_CLASS_NUMBER.value);
        this.dialog(title, "", function (isSuccessful: boolean) {
            if (isSuccessful) {
                try {
                    let result = parseFloat(Java.cast(view, Api.TextView).getText().toString());
                    !Number.isNaN(result) ? callback?.call(this, true, result <= max ? result : max) : callback?.call(this, true, NaN);
                }
                catch (e) {
                    callback?.call(this, false);
                }
            }
            else callback?.call(this, false);
        }, view);   
    }

    /**
     * Creates dialog with input text
     *
     * @public
     * @param {string} title
     * @param {?string} [hint]
     * @param {?(isSuccessful: boolean, result?: string) => void} [callback]
     */
    public inputText(title: string, hint?: string, callback?: (this: Dialog, isSuccessful: boolean, result?: string) => void) {
        let view = Api.EditText.$new(this.context);
        if (hint) view.setHint(Utils.wrap(hint));
        this.dialog(title, "", function (isSuccessful: boolean) {
            if (isSuccessful) {
                try {
                    let result = Java.cast(view, Api.TextView).getText().toString();
                    callback?.call(this, true, result);
                }
                catch (e) {
                    callback?.call(this, false);
                }
            }
            else callback?.call(this, false);
        }, view);   
    }

    /**
     * Creates collapse
     *
     * @public
     * @param {string} text
     * @param {boolean} state
     * @returns {[Java.Wrapper, Java.Wrapper]}
     */
    public collapse(text: string, state: boolean): [Java.Wrapper, Java.Wrapper] {
        let parentLayout = Api.LinearLayout.$new(this.context);
        let layout = Api.LinearLayout.$new(this.context);
        let label = this.category(`▽ ${text} ▽`);
        let params = Api.LinearLayout_Params.$new(Api.MATCH_PARENT, Api.MATCH_PARENT);
        label.backgroundColor = this.theme.collapseColor;
        params.setMargins(0, 5, 0, 0);
        parentLayout.setLayoutParams(params);
        parentLayout.setVerticalGravity(16);
        parentLayout.setOrientation(Api.VERTICAL);

        layout.setVerticalGravity(16);
        layout.setPadding(0, 5, 0, 5);
        layout.setOrientation(Api.VERTICAL);
        layout.setBackgroundColor(this.theme.layoutColor);
        layout.setVisibility(Api.GONE);

        label.padding = [0, 20, 0, 20];
        if (state) {
            layout.setVisibility(Api.VISIBLE);
            label.text = `△ ${text} △`;
        }
        label.onClickListener = () => {
            state = !state;
            if (state) {
                layout.setVisibility(Api.VISIBLE);
                label.text = `△ ${text} △`;
            }
            else {
                layout.setVisibility(Api.GONE);
                label.text = `▽ ${text} ▽`;
            }
        }
        this.add(label, parentLayout);
        this.add(layout, parentLayout);
        return [parentLayout, layout];
    }
    /**
     * Gets instance of menu
     *
     * @public
     * @static
     * @returns {Menu}
     */
    public static getInstance(): Menu {
        return this.instance;
    }
}
namespace Menu {
    export class Icon extends View {
        constructor(type: "Normal" | "Web" = "Normal", value: string) {
            super();
            this.instance = type == "Normal" ? Api.ImageView.$new(app.context) : Api.WebView.$new(app.context);
            if (value) this.image = value;
        }

        /** @internal */
        set _imageForImageView(image: string) {
            this.instance.setScaleType(Api.ScaleType.FIT_XY.value);
            this.instance.setImageBitmap(bitmap(image));
            theme.iconAlpha = Math.round(theme.iconAlpha * 255);
        }

        /** @internal */
        set _imageForWebView(image: string) {
            this.instance.loadData(`<html><head></head><body style=\"margin: 0; padding: 0\"><img src=\"${image}\" width=\"${theme.iconSize}\" height=\"${theme.iconSize}\" ></body></html>`, "text/html", "utf-8");
            this.instance.backgroundColor = Api.TRANSPARENT;
            this.instance.getSettings().setAppCacheEnabled(true);
        }

        /** Sets image */
        set image(image: string) {
            const isNormalType = this.instance.$className == Api.ImageView.$className;
            const applyDimension = Math.floor(dp(theme.iconSize));
            isNormalType ? this._imageForImageView = image : this._imageForWebView = image;
            this.alpha = theme.iconAlpha;
            this.layoutParams = Layout.LinearLayoutParams(Api.WRAP_CONTENT, Api.WRAP_CONTENT);
            this.instance.getLayoutParams().height.value = applyDimension;
            this.instance.getLayoutParams().width.value = applyDimension;
        }
    }
}
namespace Menu {
    // It's not view but we need instance holder
    // TODO: should proxy class with instance holder be created?
    // TODO: should `Gradient` class be created?
    export class GradientDrawable extends View {
        constructor() {
            super();
            this.instance = Api.GradientDrawable.$new();
        }

        set color(color: number | string) {
            this.instance.setColor(parseColor(color));
        }

        set cornerRadius(radius: number) {
            this.instance.setCornerRadius(radius);
        }
    }
}
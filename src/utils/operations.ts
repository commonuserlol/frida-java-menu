namespace Menu {
    /** Adds view to layout */
    export function add(view: View, layout: Java.Wrapper | View = Menu.instance.template.layout) {
        Java.scheduleOnMainThread(() => {
            (layout instanceof View ? layout.instance : layout).addView((view instanceof View ? view.instance : view));
        })
    }

    /** Removes view from layout */
    export function remove(view: View, layout: Java.Wrapper | View = Menu.instance.template.layout) {
        Java.scheduleOnMainThread(() => {
            (layout instanceof View ? layout.instance : layout).removeView((view instanceof View ? view.instance: view));
        })
    }
}
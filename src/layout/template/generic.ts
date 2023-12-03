namespace Menu {
    export namespace Template {
        /** Generic class for templates. Your template must extend this */
        export abstract class GenericTemplate {
            /** Menu props */
            params: Java.Wrapper; // TODO: Maybe i should add wrapper for *params
            /** Template as layout */
            me: Layout;
            /** Icon holder */
            icon: Icon;
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

            constructor() {}

            /** Initializes menu props */
            abstract initializeParams(): void;

            /** Initializes own layout */
            abstract initializeLayout(): void;

            /** Initializes icon */
            abstract initializeIcon(value: string, type: "Normal" | "Web"): void;

            /** Initializes proxy layout for scrolling feature */
            abstract initializeProxy(): void;

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
            abstract handleAdd(add: (view: View, layout?: Java.Wrapper | View) => void): void;

            /** Removes template objects */
            abstract handleRemove(remove: (view: View, layout?: Java.Wrapper | View) => void): void;

            abstract destroy(): void;
        }
    }
}
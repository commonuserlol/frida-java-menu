namespace Menu {
    /** Color configuration */
    export interface ColorConfig {
        primaryText: string,
        secondaryText: string,
        buttonBg: string,
        layoutBg: string,
        collapseBg: string,
        categoryBg: string,
        menu: string
    }

    /** Menu configuration */
    export interface MenuConfig {
        width: number,
        height: number,
        x: number,
        y: number
    }

    /** Icon configuration */
    export interface IconConfig {
        size: number,
        alpha: number
    }

    /** String configuration */
    export interface StringConfig {
        /** Text which will be shown when overlay permission missing */
        noOverlayPermission: string,
        /** Hide button label */
        hide: string,
        /** Close button label */
        close: string,
        /** When menu hidden */
        hideCallback: string,
        /** When menu killed */
        killCallback: string
    }

    /** Configuration of template
     * 
     * This defines only **REQUIRED** configuration, not final
     * 
     * Template can have other options which not documented or have poorly understood names
     */
    export declare interface GenericConfig {
        color: ColorConfig,
        menu: MenuConfig,
        icon: IconConfig,
        strings: StringConfig
    }
}
namespace Menu {
    export namespace Template {
        interface WidgetColor {
            fg: string,
            bg: string
        }

        interface ButtonColor extends WidgetColor {
            on: string,
            off: string
        }

        export interface ColorConfig {
            primaryText: string,
            secondaryText: string,
            button: ButtonColor,
            layoutBg: string,
            collapseBg: string,
            categoryBg: string,
            menu: string
        }

        export interface MenuConfig {
            width: number,
            height: number,
            x: number,
            y: number
        }

        export interface IconConfig {
            size: number,
            alpha: number
        }

        export interface StringConfig {
            noOverlayPermission: string,
            hide: string,
            close: string,
            hideCallback: string,
            killCallback: string
        }

        export declare interface GenericConfig {
            color: ColorConfig,
            menu: MenuConfig,
            icon: IconConfig,
            strings: StringConfig
        }
    }
}
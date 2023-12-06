namespace Menu {
    export namespace Template {
        export interface ColorConfig {
            primaryText: string,
            secondaryText: string,
            buttonBg: string,
            layoutBg: string,
            collapseBg: string,
            categoryBg: string,
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

        export declare type GenericConfig = ColorConfig & MenuConfig & IconConfig;
    }
}
namespace Menu {
    export declare type EmptyCallback = () => void;
    export declare type ThisCallback<T extends View> = (this: T) => void;
    export declare type ThisWithIndexCallback<T extends View> = (this: T, index: number) => void;
}
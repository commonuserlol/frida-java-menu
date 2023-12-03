namespace Menu {
    export declare const LGLConfig: Config;
    getter(Menu, "LGLConfig", () => {
        const config = new Config();
        config.primaryTextColor = "#82CAFD";
        config.secondaryTextColor = "#FFFFFF";
        config.buttonColor = "#1C262D";
        config.bgColor = "#EE1C2A35";
        config.layoutColor = "#DD141C22";
        config.collapseColor = "#222D38";
        config.categoryColor = "#2F3D4C";
        config.buttonOnOffOnColor = "#1B5E20";
        config.buttonOnOffOffColor = "#7F0000";

        config.menuWidth = 290;
        config.menuHeight = 210;
        config.menuXPosition = 50;
        config.menuYPosition = 100;

        config.iconSize = 45;
        config.iconAlpha = 0.7;

        config.noOverlayPermission = "Overlay permission required to show menu";
        config.hide = "HIDE/KILL (Hold)";
        config.hideCallback = "Icon hidden. Remember the hidden icon position";
        config.killCallback = "Menu killed";
        config.close = "MINIMIZE";

        return config;
    }, lazy);

}
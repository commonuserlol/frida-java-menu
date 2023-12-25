namespace Menu {
    /** @internal */
    export function stateHolder(state: boolean, onStateChange: (state: boolean) => void) {
        let firstSkipped = false;
        const manager = () => {
            if (!firstSkipped && state) {
                onStateChange(true);
                firstSkipped = true;
                return;
            }
            if (!firstSkipped)
                firstSkipped = true;
            state = !state;
            onStateChange(state);
        };
        if (state)
            manager();
        return manager;
    }
}
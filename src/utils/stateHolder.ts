namespace Menu {
    export function stateHolder(state: boolean, onStateChange: (state: boolean) => void) {
        let firstSkipped = false;
        return function() {
            if (!firstSkipped && state) {
                onStateChange(true);
                firstSkipped = true;
                return;
            }
            if (!firstSkipped) firstSkipped = true;
            state = !state;
            onStateChange(state);
        }
    }
}
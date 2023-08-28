namespace Menu {
    export async function sleep(ms: number = 50) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
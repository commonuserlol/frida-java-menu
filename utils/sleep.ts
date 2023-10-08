namespace Menu {
    /** Async sleep for given ms */
    export async function sleep(ms: number = 50) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
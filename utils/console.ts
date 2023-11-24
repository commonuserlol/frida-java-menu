namespace Menu {
    /** Generates random string */
    export function randomString(length: number): string {
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * length));
        }
        return result;
    }
    /** Formats text like `format("hi {}", "commonuserlol")` */
    export function format(str: String, ...obj: any): string {
        return str.replace(/\{\s*([^}\s]+)\s*\}/g, function(m, p1, offset, string) {
            return obj[p1]
        });
    }
}
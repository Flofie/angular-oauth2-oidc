import { __awaiter } from "tslib";
import { Injectable } from '@angular/core';
import { sha256 } from './js-sha256';
/**
 * Abstraction for crypto algorithms
 */
export class HashHandler {
}
export class DefaultHashHandler {
    calcHash(valueToHash, algorithm) {
        return __awaiter(this, void 0, void 0, function* () {
            // const encoder = new TextEncoder();
            // const hashArray = await window.crypto.subtle.digest(algorithm, data);
            // const data = encoder.encode(valueToHash);
            const hashArray = sha256.array(valueToHash);
            // const hashString = this.toHashString(hashArray);
            const hashString = this.toHashString2(hashArray);
            return hashString;
        });
    }
    toHashString2(byteArray) {
        let result = '';
        for (let e of byteArray) {
            result += String.fromCharCode(e);
        }
        return result;
    }
    toHashString(buffer) {
        const byteArray = new Uint8Array(buffer);
        let result = '';
        for (let e of byteArray) {
            result += String.fromCharCode(e);
        }
        return result;
    }
}
DefaultHashHandler.decorators = [
    { type: Injectable }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaC1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vcHJvamVjdHMvbGliL3NyYy90b2tlbi12YWxpZGF0aW9uL2hhc2gtaGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUUzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sYUFBYSxDQUFDO0FBRXJDOztHQUVHO0FBQ0gsTUFBTSxPQUFnQixXQUFXO0NBRWhDO0FBR0QsTUFBTSxPQUFPLGtCQUFrQjtJQUN2QixRQUFRLENBQUMsV0FBbUIsRUFBRSxTQUFpQjs7WUFDbkQscUNBQXFDO1lBQ3JDLHdFQUF3RTtZQUN4RSw0Q0FBNEM7WUFFNUMsTUFBTSxTQUFTLEdBQUksTUFBYyxDQUFDLEtBQUssQ0FBQyxXQUFXLENBQUMsQ0FBQztZQUNyRCxtREFBbUQ7WUFDbkQsTUFBTSxVQUFVLEdBQUcsSUFBSSxDQUFDLGFBQWEsQ0FBQyxTQUFTLENBQUMsQ0FBQztZQUVqRCxPQUFPLFVBQVUsQ0FBQztRQUNwQixDQUFDO0tBQUE7SUFFRCxhQUFhLENBQUMsU0FBbUI7UUFDL0IsSUFBSSxNQUFNLEdBQUcsRUFBRSxDQUFDO1FBQ2hCLEtBQUssSUFBSSxDQUFDLElBQUksU0FBUyxFQUFFO1lBQ3ZCLE1BQU0sSUFBSSxNQUFNLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ2xDO1FBQ0QsT0FBTyxNQUFNLENBQUM7SUFDaEIsQ0FBQztJQUVELFlBQVksQ0FBQyxNQUFtQjtRQUM5QixNQUFNLFNBQVMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUN6QyxJQUFJLE1BQU0sR0FBRyxFQUFFLENBQUM7UUFDaEIsS0FBSyxJQUFJLENBQUMsSUFBSSxTQUFTLEVBQUU7WUFDdkIsTUFBTSxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDbEM7UUFDRCxPQUFPLE1BQU0sQ0FBQztJQUNoQixDQUFDOzs7WUE3QkYsVUFBVSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcblxuaW1wb3J0IHsgc2hhMjU2IH0gZnJvbSAnLi9qcy1zaGEyNTYnO1xuXG4vKipcbiAqIEFic3RyYWN0aW9uIGZvciBjcnlwdG8gYWxnb3JpdGhtc1xuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgSGFzaEhhbmRsZXIge1xuICBhYnN0cmFjdCBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPjtcbn1cblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIERlZmF1bHRIYXNoSGFuZGxlciBpbXBsZW1lbnRzIEhhc2hIYW5kbGVyIHtcbiAgYXN5bmMgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIC8vIGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbiAgICAvLyBjb25zdCBoYXNoQXJyYXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhKTtcbiAgICAvLyBjb25zdCBkYXRhID0gZW5jb2Rlci5lbmNvZGUodmFsdWVUb0hhc2gpO1xuXG4gICAgY29uc3QgaGFzaEFycmF5ID0gKHNoYTI1NiBhcyBhbnkpLmFycmF5KHZhbHVlVG9IYXNoKTtcbiAgICAvLyBjb25zdCBoYXNoU3RyaW5nID0gdGhpcy50b0hhc2hTdHJpbmcoaGFzaEFycmF5KTtcbiAgICBjb25zdCBoYXNoU3RyaW5nID0gdGhpcy50b0hhc2hTdHJpbmcyKGhhc2hBcnJheSk7XG5cbiAgICByZXR1cm4gaGFzaFN0cmluZztcbiAgfVxuXG4gIHRvSGFzaFN0cmluZzIoYnl0ZUFycmF5OiBudW1iZXJbXSkge1xuICAgIGxldCByZXN1bHQgPSAnJztcbiAgICBmb3IgKGxldCBlIG9mIGJ5dGVBcnJheSkge1xuICAgICAgcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoZSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICB0b0hhc2hTdHJpbmcoYnVmZmVyOiBBcnJheUJ1ZmZlcikge1xuICAgIGNvbnN0IGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGJ1ZmZlcik7XG4gICAgbGV0IHJlc3VsdCA9ICcnO1xuICAgIGZvciAobGV0IGUgb2YgYnl0ZUFycmF5KSB7XG4gICAgICByZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIGhleFN0cmluZyhidWZmZXIpIHtcbiAgLy8gICAgIGNvbnN0IGJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KGJ1ZmZlcik7XG4gIC8vICAgICBjb25zdCBoZXhDb2RlcyA9IFsuLi5ieXRlQXJyYXldLm1hcCh2YWx1ZSA9PiB7XG4gIC8vICAgICAgIGNvbnN0IGhleENvZGUgPSB2YWx1ZS50b1N0cmluZygxNik7XG4gIC8vICAgICAgIGNvbnN0IHBhZGRlZEhleENvZGUgPSBoZXhDb2RlLnBhZFN0YXJ0KDIsICcwJyk7XG4gIC8vICAgICAgIHJldHVybiBwYWRkZWRIZXhDb2RlO1xuICAvLyAgICAgfSk7XG5cbiAgLy8gICAgIHJldHVybiBoZXhDb2Rlcy5qb2luKCcnKTtcbiAgLy8gICB9XG5cbiAgLy8gdG9IYXNoU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XG4gIC8vICAgbGV0IHJlc3VsdCA9ICcnO1xuICAvLyAgIGZvciAobGV0IGkgPSAwOyBpIDwgaGV4U3RyaW5nLmxlbmd0aDsgaSArPSAyKSB7XG4gIC8vICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XG4gIC8vICAgICBsZXQgbnVtID0gcGFyc2VJbnQoaGV4RGlnaXQsIDE2KTtcbiAgLy8gICAgIHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKG51bSk7XG4gIC8vICAgfVxuICAvLyAgIHJldHVybiByZXN1bHQ7XG4gIC8vIH1cbn1cbiJdfQ==
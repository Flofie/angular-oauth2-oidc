import { OAuthStorage, OAuthLogger } from './types';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthService } from './oauth-service';
import { UrlHelperService } from './url-helper.service';
import { OAuthModuleConfig } from './oauth-module.config';
import { OAuthResourceServerErrorHandler, OAuthNoopResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
import { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
import { ValidationHandler } from './token-validation/validation-handler';
import { NullValidationHandler } from './token-validation/null-validation-handler';
import { createDefaultLogger, createDefaultStorage } from './factories';
import { HashHandler, DefaultHashHandler } from './token-validation/hash-handler';
export class OAuthModule {
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
        return {
            ngModule: OAuthModule,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: HashHandler, useClass: DefaultHashHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler
                },
                { provide: OAuthModuleConfig, useValue: config },
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: DefaultOAuthInterceptor,
                    multi: true
                }
            ]
        };
    }
}
OAuthModule.decorators = [
    { type: NgModule, args: [{
                imports: [CommonModule],
                declarations: [],
                exports: []
            },] }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3Byb2plY3RzL2xpYi9zcmMvYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsWUFBWSxFQUFFLFdBQVcsRUFBRSxNQUFNLFNBQVMsQ0FBQztBQUNwRCxPQUFPLEVBQUUsUUFBUSxFQUF1QixNQUFNLGVBQWUsQ0FBQztBQUM5RCxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDL0MsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFFekQsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQy9DLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBRXhELE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxNQUFNLHVCQUF1QixDQUFDO0FBQzFELE9BQU8sRUFDTCwrQkFBK0IsRUFDL0IsbUNBQW1DLEVBQ3BDLE1BQU0sOENBQThDLENBQUM7QUFDdEQsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sMENBQTBDLENBQUM7QUFDbkYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sdUNBQXVDLENBQUM7QUFDMUUsT0FBTyxFQUFFLHFCQUFxQixFQUFFLE1BQU0sNENBQTRDLENBQUM7QUFDbkYsT0FBTyxFQUFFLG1CQUFtQixFQUFFLG9CQUFvQixFQUFFLE1BQU0sYUFBYSxDQUFDO0FBQ3hFLE9BQU8sRUFDTCxXQUFXLEVBQ1gsa0JBQWtCLEVBQ25CLE1BQU0saUNBQWlDLENBQUM7QUFPekMsTUFBTSxPQUFPLFdBQVc7SUFDdEIsTUFBTSxDQUFDLE9BQU8sQ0FDWixTQUE0QixJQUFJLEVBQ2hDLHNCQUFzQixHQUFHLHFCQUFxQjtRQUU5QyxPQUFPO1lBQ0wsUUFBUSxFQUFFLFdBQVc7WUFDckIsU0FBUyxFQUFFO2dCQUNULFlBQVk7Z0JBQ1osZ0JBQWdCO2dCQUNoQixFQUFFLE9BQU8sRUFBRSxXQUFXLEVBQUUsVUFBVSxFQUFFLG1CQUFtQixFQUFFO2dCQUN6RCxFQUFFLE9BQU8sRUFBRSxZQUFZLEVBQUUsVUFBVSxFQUFFLG9CQUFvQixFQUFFO2dCQUMzRCxFQUFFLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxRQUFRLEVBQUUsc0JBQXNCLEVBQUU7Z0JBQ2hFLEVBQUUsT0FBTyxFQUFFLFdBQVcsRUFBRSxRQUFRLEVBQUUsa0JBQWtCLEVBQUU7Z0JBQ3REO29CQUNFLE9BQU8sRUFBRSwrQkFBK0I7b0JBQ3hDLFFBQVEsRUFBRSxtQ0FBbUM7aUJBQzlDO2dCQUNELEVBQUUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUU7Z0JBQ2hEO29CQUNFLE9BQU8sRUFBRSxpQkFBaUI7b0JBQzFCLFFBQVEsRUFBRSx1QkFBdUI7b0JBQ2pDLEtBQUssRUFBRSxJQUFJO2lCQUNaO2FBQ0Y7U0FDRixDQUFDO0lBQ0osQ0FBQzs7O1lBL0JGLFFBQVEsU0FBQztnQkFDUixPQUFPLEVBQUUsQ0FBQyxZQUFZLENBQUM7Z0JBQ3ZCLFlBQVksRUFBRSxFQUFFO2dCQUNoQixPQUFPLEVBQUUsRUFBRTthQUNaIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgT0F1dGhTdG9yYWdlLCBPQXV0aExvZ2dlciB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgTmdNb2R1bGUsIE1vZHVsZVdpdGhQcm92aWRlcnMgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IENvbW1vbk1vZHVsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XG5pbXBvcnQgeyBIVFRQX0lOVEVSQ0VQVE9SUyB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcblxuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi9vYXV0aC1zZXJ2aWNlJztcbmltcG9ydCB7IFVybEhlbHBlclNlcnZpY2UgfSBmcm9tICcuL3VybC1oZWxwZXIuc2VydmljZSc7XG5cbmltcG9ydCB7IE9BdXRoTW9kdWxlQ29uZmlnIH0gZnJvbSAnLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcbmltcG9ydCB7XG4gIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIsXG4gIE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyXG59IGZyb20gJy4vaW50ZXJjZXB0b3JzL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyJztcbmltcG9ydCB7IERlZmF1bHRPQXV0aEludGVyY2VwdG9yIH0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvcic7XG5pbXBvcnQgeyBWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHsgTnVsbFZhbGlkYXRpb25IYW5kbGVyIH0gZnJvbSAnLi90b2tlbi12YWxpZGF0aW9uL251bGwtdmFsaWRhdGlvbi1oYW5kbGVyJztcbmltcG9ydCB7IGNyZWF0ZURlZmF1bHRMb2dnZXIsIGNyZWF0ZURlZmF1bHRTdG9yYWdlIH0gZnJvbSAnLi9mYWN0b3JpZXMnO1xuaW1wb3J0IHtcbiAgSGFzaEhhbmRsZXIsXG4gIERlZmF1bHRIYXNoSGFuZGxlclxufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcblxuQE5nTW9kdWxlKHtcbiAgaW1wb3J0czogW0NvbW1vbk1vZHVsZV0sXG4gIGRlY2xhcmF0aW9uczogW10sXG4gIGV4cG9ydHM6IFtdXG59KVxuZXhwb3J0IGNsYXNzIE9BdXRoTW9kdWxlIHtcbiAgc3RhdGljIGZvclJvb3QoXG4gICAgY29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZyA9IG51bGwsXG4gICAgdmFsaWRhdGlvbkhhbmRsZXJDbGFzcyA9IE51bGxWYWxpZGF0aW9uSGFuZGxlclxuICApOiBNb2R1bGVXaXRoUHJvdmlkZXJzPE9BdXRoTW9kdWxlPiB7XG4gICAgcmV0dXJuIHtcbiAgICAgIG5nTW9kdWxlOiBPQXV0aE1vZHVsZSxcbiAgICAgIHByb3ZpZGVyczogW1xuICAgICAgICBPQXV0aFNlcnZpY2UsXG4gICAgICAgIFVybEhlbHBlclNlcnZpY2UsXG4gICAgICAgIHsgcHJvdmlkZTogT0F1dGhMb2dnZXIsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRMb2dnZXIgfSxcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRTdG9yYWdlIH0sXG4gICAgICAgIHsgcHJvdmlkZTogVmFsaWRhdGlvbkhhbmRsZXIsIHVzZUNsYXNzOiB2YWxpZGF0aW9uSGFuZGxlckNsYXNzIH0sXG4gICAgICAgIHsgcHJvdmlkZTogSGFzaEhhbmRsZXIsIHVzZUNsYXNzOiBEZWZhdWx0SGFzaEhhbmRsZXIgfSxcbiAgICAgICAge1xuICAgICAgICAgIHByb3ZpZGU6IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIsXG4gICAgICAgICAgdXNlQ2xhc3M6IE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyXG4gICAgICAgIH0sXG4gICAgICAgIHsgcHJvdmlkZTogT0F1dGhNb2R1bGVDb25maWcsIHVzZVZhbHVlOiBjb25maWcgfSxcbiAgICAgICAge1xuICAgICAgICAgIHByb3ZpZGU6IEhUVFBfSU5URVJDRVBUT1JTLFxuICAgICAgICAgIHVzZUNsYXNzOiBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvcixcbiAgICAgICAgICBtdWx0aTogdHJ1ZVxuICAgICAgICB9XG4gICAgICBdXG4gICAgfTtcbiAgfVxufVxuIl19
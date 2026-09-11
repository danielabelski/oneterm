package remote

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cast"
	"go.uber.org/zap"

	"github.com/veops/oneterm/pkg/cache"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/logger"
)

var (
	RC = resty.NewWithClient(&http.Client{}).SetRetryCount(3)
)

// CopyContext preserves legacy Gin context semantics without retaining its pooled instance.
func CopyContext(ctx context.Context) context.Context {
	if request, ok := ctx.(*gin.Context); ok {
		return request.Copy()
	}
	return ctx
}

func GetAclToken(ctx context.Context) (res string, err error) {
	res, err = cache.RC.Get(ctx, "aclToken").Result()
	if err == nil {
		return
	}
	aclConfig := config.Cfg.Auth.Acl

	url := fmt.Sprintf("%s%s", aclConfig.Url, "/acl/apps/token")
	secretHash := md5.Sum([]byte(aclConfig.SecretKey))
	secretKey := hex.EncodeToString(secretHash[:])

	data := make(map[string]string)
	resp, err := RC.R().
		SetContext(CopyContext(ctx)).
		SetBody(map[string]any{"app_id": aclConfig.AppId, "secret_key": secretKey}).
		SetResult(&data).
		Post(url)
	if err = HandleErr(err, resp, func(dt map[string]any) bool { return dt["token"] != "" }); err != nil {
		return
	}

	res = data["token"]
	_, err = cache.RC.SetNX(ctx, "aclToken", res, time.Hour).Result()
	return
}

func HandleErr(e error, resp *resty.Response, isOk func(dt map[string]any) bool) (err error) {
	pc, _, _, _ := runtime.Caller(1)

	defer func() {
		if err != nil {
			fields := []zap.Field{zap.String("error_type", fmt.Sprintf("%T", err))}
			if resp != nil {
				fields = append(fields, zap.Int("status", resp.StatusCode()))
				if resp.Request != nil {
					fields = append(fields, zap.String("method", resp.Request.Method))
					if endpoint, parseErr := url.Parse(resp.Request.URL); parseErr == nil {
						fields = append(fields, zap.String("host", endpoint.Host), zap.String("path", endpoint.Path))
					}
				}
			}
			logger.L().Error(fmt.Sprintf("%s failed", runtime.FuncForPC(pc).Name()), fields...)
		}
	}()

	err = e
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("upstream response is unavailable")
	}

	dt := make(map[string]any)
	err = json.Unmarshal(resp.Body(), &dt)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 200 || (isOk != nil && !isOk(dt)) {
		err = &RemoteError{
			HttpCode: resp.StatusCode(),
			Resp:     dt,
		}
		return
	}
	return nil
}

type RemoteError struct {
	HttpCode int
	Resp     map[string]any
}

func (r *RemoteError) Error() string {
	return cast.ToString(r.Resp["message"])
}

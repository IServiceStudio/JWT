using HS256.Model;

namespace HS256.Service
{
    public interface IJWTService
    {
        string GetToken(User user);
    }
}

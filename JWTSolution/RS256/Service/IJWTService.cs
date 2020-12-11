using RS256.Model;

namespace RS256.Service
{
    public interface IJWTService
    {
        string GetToken(User user);
    }
}
